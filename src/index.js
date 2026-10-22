// Secrets Broker — public demo Worker.
//
// Every credential, agent and audit line in here is virtual. Nothing is read
// from or written to a real vault. The point of the demo is to let someone click
// through the real UI and the real read path (browser-side key derivation, real
// encryption at rest) without handing over any real secret.
//
// Design rules that follow from "public demo":
//  - The admin password is fixed and printed on the login page.
//  - Nothing persists across a request except a per-isolate cache. There is no
//    Durable Object, no D1, no writes an attacker could keep.
//  - Writes are allowed so the UI is explorable, but they only mutate memory and
//    are labelled as demo writes in the audit trail.
import { uiHtml } from './ui.js'
import {
  demoVault, demoItemIdByName, DEMO_EMAIL, DEMO_MASTER_PASSWORD,
  DEMO_KDF_ITERATIONS, DEMO_USER_KEY, demoUserKeyB64,
} from './vault.js'
import { decryptCipherRow, extractSecret, extractUsername, extractTotp, encryptStr, bytesToB64 } from './crypto.js'

const DEMO_ADMIN_PASSWORD = 'demo'
const SESSION_COOKIE = 'demo_session'

const encoder = new TextEncoder()
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
})
const fail = (message, status = 400) => json({ error: message }, status)
const htmlResponse = (body, status = 200) => new Response(body, {
  status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
})
const nowIso = () => new Date().toISOString()

// ── In-memory session ───────────────────────────────────────────────────────
// A demo session is one cookie holding an opaque id. The unlocked key lives in
// the isolate that issued it, so a cold start simply asks the visitor to unlock
// again. Nothing here is a security boundary: the vault is fake.
const sessions = new Map()

function readCookie(request, name) {
  const header = request.headers.get('cookie') ?? ''
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=')
    if (key === name) return rest.join('=')
  }
  return ''
}

function currentSession(request) {
  const id = readCookie(request, SESSION_COOKIE)
  if (!id) return null
  const session = sessions.get(id)
  if (!session) return null
  if (session.expiresAt && session.expiresAt < Date.now()) { sessions.delete(id); return null }
  return session
}

// The vault keys the worker needs to decrypt a row. In the demo the user key is
// fixed and public, so every session carries it from the start; a real
// installation only has these after the browser has unlocked the vault.
const VAULT_KEYS = {
  email: DEMO_EMAIL,
  symEncKey: bytesToB64(DEMO_USER_KEY.slice(0, 32)),
  symMacKey: bytesToB64(DEMO_USER_KEY.slice(32, 64)),
}

const sessionCookie = (id) => `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`

// ── Demo state ──────────────────────────────────────────────────────────────
// Mutable in-memory state derived from the virtual vault. Reset whenever the
// isolate restarts, which is the intended behaviour for a demo.
let state = null
async function demoState() {
  if (state) return state
  const vault = await demoVault()
  const now = Date.now()
  const agents = {}
  for (const agent of vault.agents) {
    agents[agent.name] = {
      name: agent.name, alias: agent.alias ?? '', note: agent.note ?? '',
      allow: agent.allow ?? [], groups: [], allowAll: agent.allowAll === true,
      write: agent.write === true, account: DEMO_EMAIL,
      // The UI only needs to know a token exists; the value is never exposed.
      tokenPreview: 'demo-' + agent.name + '-token',
    }
  }
  const credentialKinds = {}
  const fillPolicies = {}
  const plaintextReadPolicies = {}
  for (const row of vault.ciphers) {
    const demo = row.demo
    if (!demo?.kind) continue
    credentialKinds[row.id] = demo.kind
    if (demo.kind === 'web') {
      fillPolicies[row.id] = { itemId: row.id, accountId: DEMO_EMAIL, origins: demo.origins, actions: demo.actions, policyRevision: 'demo-rev-' + row.id, autoApprove: false, updatedAt: nowIso() }
    }
    if (demo.kind === 'api' && demo.readAllowed) {
      plaintextReadPolicies[row.id] = { itemId: row.id, accountId: DEMO_EMAIL, expiresAt: Date.now() + 30 * 86400e3, createdAt: nowIso() }
    }
  }
  // A little history so the charts, the donut and the globe are not empty.
  const audit = demoAudit(vault)
  state = {
    agents,
    grants: demoGrants(vault),
    pending: {},
    audit,
    itemIds: Object.fromEntries(vault.seed.map((entry, i) => [entry.name, 'demo-item-' + (i + 1)])),
    credentialKinds, fillPolicies, plaintextReadPolicies,
    policies: {},
    settings: { vaultEmail: DEMO_EMAIL, notifications: {}, requireClassification: true, siteName: 'Secrets Broker' },
    profile: { name: 'Demo User', email: DEMO_EMAIL },
    demoWrites: [],
  }
  return state
}

// Six plausible-looking agents and a spread of requests, so the globe, the
// donut, the ranking and the trend all have something real-shaped to draw.
const DEMO_VISITS = [
  { agent: 'muse', item: 'openai-prod', lat: 37.77, lon: -122.42, country: 'US', city: 'San Francisco', hours: 1 },
  { agent: 'codex', item: 'github-actions', lat: 51.51, lon: -0.13, country: 'GB', city: 'London', hours: 2 },
  { agent: 'muse', item: 'openai-prod', lat: 52.52, lon: 13.40, country: 'DE', city: 'Berlin', hours: 3 },
  { agent: 'reporter', item: 'postgres-analytics', lat: 35.68, lon: 139.69, country: 'JP', city: 'Tokyo', hours: 5 },
  { agent: 'codex', item: 'stripe-live', lat: 1.35, lon: 103.82, country: 'SG', city: 'Singapore', hours: 7 },
  { agent: 'muse', item: 'openai-prod', lat: 30.67, lon: 104.07, country: 'CN', city: 'Chengdu', hours: 9 },
  { agent: 'reporter', item: 'postgres-analytics', lat: -33.87, lon: 151.21, country: 'AU', city: 'Sydney', hours: 12 },
  { agent: 'codex', item: 'openai-prod', lat: 48.86, lon: 2.35, country: 'FR', city: 'Paris', hours: 15 },
  { agent: 'muse', item: 'stripe-live', lat: -23.55, lon: -46.63, country: 'BR', city: 'Sao Paulo', hours: 18 },
  { agent: 'reporter', item: 'postgres-analytics', lat: 19.08, lon: 72.88, country: 'IN', city: 'Mumbai', hours: 21 },
  { agent: 'muse', item: 'github-actions', lat: 40.71, lon: -74.0, country: 'US', city: 'New York', hours: 23 },
  { agent: 'codex', item: 'stripe-live', lat: 25.20, lon: 55.27, country: 'AE', city: 'Dubai', hours: 26 },
]

function demoAudit(vault) {
  const out = []
  const now = Date.now()
  for (const visit of DEMO_VISITS) {
    out.push({
      time: new Date(now - visit.hours * 3600e3).toISOString(),
      event: 'secret.read', agent: visit.agent, name: visit.item, mode: 'mcp',
      geo: { lat: visit.lat, lon: visit.lon, country: visit.country, city: visit.city, known: true },
    })
  }
  // A denial, so the "refused" path is visible too.
  out.push({ time: new Date(now - 40 * 60e3).toISOString(), event: 'secret.read-deny', agent: 'codex', name: 'legacy-smtp', reason: 'unclassified-credential', geo: { lat: 51.51, lon: -0.13, country: 'GB', city: 'London', known: true } })
  out.sort((a, b) => (a.time < b.time ? 1 : -1))
  return out
}

function demoGrants(vault) {
  const now = Date.now()
  const itemId = (name) => vault.seed.findIndex((entry) => entry.name === name) >= 0 ? 'demo-item-' + (vault.seed.findIndex((entry) => entry.name === name) + 1) : ''
  const grant = (agent, name, seconds, maxReads, extra = {}) => ({
    agent, name, mode: 'share', createdAt: new Date(now - 3600e3).toISOString(),
    expiresAt: seconds ? now + seconds * 1000 : 0, reads: 1, maxReads: maxReads ?? null,
    revokedAt: null, account: DEMO_EMAIL, itemId: itemId(name), ...extra,
  })
  return {
    ['muse\u0000openai-prod']: grant('muse', 'openai-prod', 0, null),
    ['muse\u0000stripe-live']: grant('muse', 'stripe-live', 7 * 86400, null),
    ['codex\u0000github-actions']: grant('codex', 'github-actions', 3600, 5),
    ['codex\u0000stripe-live']: grant('codex', 'stripe-live', 0, null),
    ['reporter\u0000postgres-analytics']: grant('reporter', 'postgres-analytics', 86400, 20),
    // Deliberately expired, so the "已过期 + click to extend" row is visible.
    ['muse\u0000github-actions']: grant('muse', 'github-actions', 0, null, { expiresAt: now - 7200e3 }),
  }
}

// ── Handlers ────────────────────────────────────────────────────────────────
async function bootstrap() {
  const vault = await demoVault()
  return {
    email: DEMO_EMAIL,
    kdfType: 0,
    kdfIterations: DEMO_KDF_ITERATIONS,
    // The profile key is only used by the real client to unwrap the user key.
    // The demo returns the wrapped form for fidelity, but the real key never
    // leaves this file.
    profileKey: vault.users[0].key,
    demo: { masterPassword: DEMO_MASTER_PASSWORD, adminPassword: DEMO_ADMIN_PASSWORD, userKey: demoUserKeyB64() },
  }
}

async function listItems(session) {
  // A session without the vault keys cannot decrypt; fall back to the demo keys.
  const keyed = session && session.symEncKey ? session : { ...VAULT_KEYS, ...(session || {}) }
  const vault = await demoVault()
  const current = await demoState()
  const out = []
  for (const row of vault.ciphers) {
    const decrypted = await decryptCipherRow(row, keyed)
    const grants = Object.values(current.grants).filter((grant) => grant.name === decrypted.name && !grant.revokedAt)
    out.push({
      id: row.id,
      name: decrypted.name,
      username: extractUsername(decrypted),
      totp: extractTotp(decrypted),
      url: row.demo?.origins?.[0] ?? '',
      group: groupOf(vault, row),
      noApproval: grants.some((grant) => grant.noApproval === true),
      expiresAt: 0,
      lastActivityAt: lastActivityFor(current.audit, decrypted.name),
      lastActor: lastActorFor(current.audit, decrypted.name),
    })
  }
  out.sort((a, b) => a.name.localeCompare(b.name))
  return out
}

function groupOf(vault, row) {
  const index = vault.ciphers.indexOf(row)
  return index >= 0 ? (['api/prod', 'api/prod', 'api/ci', 'web', 'web', 'db', 'mail'][index] ?? '') : ''
}

function lastActivityFor(audit, name) {
  const hit = audit.find((entry) => entry.name === name)
  return hit ? hit.time : ''
}

function lastActorFor(audit, name) {
  const hit = audit.find((entry) => entry.name === name)
  return hit ? hit.agent : ''
}

function statsFor(current, range) {
  const rangeMs = range === '7d' ? 7 * 86400e3 : range === '30d' ? 30 * 86400e3 : 24 * 3600e3
  const start = Date.now() - rangeMs
  const reads = (current.audit ?? []).filter((entry) => entry.event === 'secret.read' && Date.parse(entry.time) >= start)
  // Fixed buckets, so the chart has a slot for every hour even when it is empty.
  const bucketCount = range === '24h' ? 24 : range === '7d' ? 28 : 30
  const bucketMs = rangeMs / bucketCount
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const from = start + index * bucketMs
    const count = reads.filter((entry) => { const time = Date.parse(entry.time); return time >= from && time < from + bucketMs }).length
    const date = new Date(from)
    return { label: range === '24h' ? String(date.getHours()).padStart(2, '0') + ':00' : (date.getMonth() + 1) + '/' + date.getDate(), count }
  })
  const countBy = (field) => {
    const map = new Map()
    for (const entry of reads) { const key = entry[field] ?? '未知'; map.set(key, (map.get(key) ?? 0) + 1) }
    return [...map.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count)
  }
  const grants = Object.values(current.grants ?? {}).filter((grant) => !grant.revokedAt && (!grant.expiresAt || grant.expiresAt > Date.now()))
  return {
    totalReads: reads.length,
    activeAgents: new Set(reads.map((entry) => entry.agent).filter(Boolean)).size,
    pending: Object.keys(current.pending ?? {}).length,
    activeGrants: grants.length,
    buckets,
    topItems: countBy('name').slice(0, 6),
    topAgents: countBy('agent'),
  }
}

async function publicState(session, request) {
  const current = await demoState()
  const vault = await demoVault()
  const items = await listItems(session)
  return {
    agents: Object.values(current.agents).map((agent) => ({ ...agent, oauth: false, createdAt: nowIso(), expiresAt: null })),
    grants: Object.values(current.grants ?? {}),
    pending: Object.values(current.pending ?? {}),
    audit: (current.audit ?? []).slice(0, 200),
    policies: current.policies ?? {},
    itemGroups: Object.fromEntries(items.map((item) => [item.name, item.group])),
    profile: current.profile,
    requireClassification: current.settings.requireClassification !== false,
    legacyUnbound: [],
    fillPolicies: {
      executionLayer: false,
      items: Object.entries(current.credentialKinds ?? {}).map(([itemId, kind]) => ({
        itemId, kind,
        itemName: vault.seed[Number(String(itemId).replace('demo-item-', '')) - 1]?.name ?? '',
        origins: current.fillPolicies?.[itemId]?.origins ?? [],
        actions: current.fillPolicies?.[itemId]?.actions ?? [],
        plaintextRead: Boolean(current.plaintextReadPolicies?.[itemId]),
        plaintextReadExpiresAt: current.plaintextReadPolicies?.[itemId]?.expiresAt ?? 0,
      })),
    },
    oauthClients: [],
    transfers: [],
    reminders: [],
    stats: statsFor(current, '24h'),
    demo: { writes: current.demoWrites.length, items: items.length },
  }
}

// ── Router ──────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)

    // Static files (the globe bundle and the earth texture) are served by
    // wrangler's assets binding before this worker ever runs, so there is nothing
    // to handle here. A fallback would only hide a misconfigured deploy.

    if (url.pathname === '/' || url.pathname === '/index.html') {
      return htmlResponse(uiHtml)
    }
    if (url.pathname === '/login') {
      return htmlResponse(loginPage())
    }
    if (url.pathname === '/logo.png' || url.pathname === '/favicon.ico') {
      return new Response(null, { status: 204 })
    }

    if (url.pathname === '/api/login' && request.method === 'POST') {
      const body = await request.json().catch(() => ({}))
      if (String(body.password ?? '') !== DEMO_ADMIN_PASSWORD) return fail('演示密码是 ' + DEMO_ADMIN_PASSWORD, 401)
      const id = crypto.randomUUID()
      sessions.set(id, { id, expiresAt: Date.now() + 3600e3, ...VAULT_KEYS })
      return json({ ok: true, demo: true }, 200, { 'set-cookie': sessionCookie(id) })
    }
    if (url.pathname === '/api/logout' && request.method === 'POST') {
      const id = readCookie(request, SESSION_COOKIE)
      if (id) sessions.delete(id)
      return json({ ok: true }, 200, { 'set-cookie': `${SESSION_COOKIE}=; Path=/; Max-Age=0` })
    }

    // Everything below needs the demo session.
    const session = currentSession(request)
    const needsAuth = url.pathname.startsWith('/api/') || url.pathname === '/oidc/callback'
    if (needsAuth && !session) return fail('unauthorized', 401)

    if (url.pathname === '/api/bootstrap') return json(await bootstrap())
    if (url.pathname === '/api/me') {
      const current = await demoState()
      return json({
        email: DEMO_EMAIL, name: current.profile.name, avatarUrl: '',
        siteName: 'Secrets Broker · 演示', unlocked: true,
        expiresAt: session.expiresAt, pending: Object.keys(current.pending ?? {}).length,
      })
    }
    if (url.pathname === '/api/unlock' && request.method === 'POST') {
      // The demo has nothing to unwrap: the session is already the unlocked
      // vault. Accepting the call keeps the real unlock flow working end to end.
      return json({ ok: true, expiresAt: 0, permanent: true, demo: true })
    }
    if (url.pathname === '/api/lock' && request.method === 'POST') {
      const id = readCookie(request, SESSION_COOKIE)
      if (id) sessions.delete(id)
      return json({ ok: true }, 200, { 'set-cookie': `${SESSION_COOKIE}=; Path=/; Max-Age=0` })
    }
    if (url.pathname === '/api/state') return json(await publicState(session, request))
    if (url.pathname === '/api/items') return json({ items: await listItems(session), completedTransfers: [] })
    if (url.pathname === '/api/stats') {
      const current = await demoState()
      return json(statsFor(current, url.searchParams.get('range') ?? '24h'))
    }
    if (url.pathname === '/api/geo/events') {
      const current = await demoState()
      const range = url.searchParams.get('range') ?? '24h'
      const windowMs = range === '1h' ? 3600e3 : range === '7d' ? 7 * 86400e3 : 86400e3
      const since = Date.now() - windowMs
      const sinceSeq = Number(url.searchParams.get('sinceSeq') ?? 0)
      const events = current.audit
        .filter((entry) => entry.geo?.known && Date.parse(entry.time) >= since)
        .map((entry, i) => ({ id: 'evt_' + (i + 1), seq: i + 1, at: entry.time, agent: entry.agent, action: entry.event, ok: entry.event !== 'secret.read-deny', geo: entry.geo }))
        .filter((entry) => entry.seq > sinceSeq)
      return json({
        ok: true, enabled: true, range,
        operator: { known: true, lat: 31.23, lon: 121.47, country: 'CN', city: 'Shanghai' },
        broker: { lat: 31.23, lon: 121.47, code: 'CN' },
        events, cursor: events.length ? events[events.length - 1].seq : sinceSeq, total: events.length,
      })
    }
    if (url.pathname === '/api/settings') {
      const current = await demoState()
      if (request.method === 'GET') {
        return json({ notifications: { telegram: {}, ntfy: {}, gotify: {}, wxpush: {}, templates: {} }, vaultFolder: '', vaultEmail: DEMO_EMAIL, siteName: 'Secrets Broker · 演示', requireClassification: current.settings.requireClassification !== false, demo: true })
      }
      const body = await request.json().catch(() => ({}))
      if (typeof body.requireClassification === 'boolean') {
        current.settings.requireClassification = body.requireClassification
        current.demoWrites.push({ at: nowIso(), what: 'requireClassification', value: body.requireClassification })
      }
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/security') return json({ passwordSource: 'demo', totpEnabled: false, totpPending: false })
    if (url.pathname === '/api/profile') return json({ profile: (await demoState()).profile, oidcEnabled: false, oidcProviders: [], oidcBindings: {} })
    if (url.pathname === '/api/sessions') return json({ sessions: [{ id: 'demo', ua: request.headers.get('user-agent') ?? '', ip: request.headers.get('cf-connecting-ip') ?? '', createdAt: nowIso(), lastSeen: nowIso(), current: true }] })
    if (url.pathname === '/api/oidc/status') return json({ enabled: false, providers: [], issuer: '' })
    if (url.pathname === '/api/accounts') return json({ accounts: [{ email: DEMO_EMAIL }] })
    if (url.pathname === '/api/folders') {
      const vault = await demoVault()
      return json({ folders: vault.folders.map((folder, i) => ({ id: folder.id, name: ['api', 'web'][i] ?? '' })) })
    }
    if (url.pathname === '/api/fill/policy' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const name = String(body.item ?? '')
      const itemId = await demoItemIdByName(name)
      if (!itemId) return fail('item not found', 404)
      const kind = String(body.kind ?? '')
      if (kind !== 'api' && kind !== 'web') return fail('kind must be api or web', 400)
      current.credentialKinds[itemId] = kind
      if (kind === 'web') {
        const origins = (Array.isArray(body.origins) ? body.origins : []).map(String).filter(Boolean)
        if (!origins.length) return fail('web credentials need at least one https origin', 400)
        current.fillPolicies[itemId] = { itemId, accountId: DEMO_EMAIL, origins, actions: ['login'], policyRevision: crypto.randomUUID(), autoApprove: false, updatedAt: nowIso() }
      } else {
        delete current.fillPolicies[itemId]
      }
      current.demoWrites.push({ at: nowIso(), what: 'classify', item: name, kind })
      return json({ ok: true, itemId, kind, demo: true })
    }
    if (url.pathname === '/api/fill/policy/delete' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const itemId = await demoItemIdByName(String(body.item ?? ''))
      if (!itemId) return fail('item not found', 404)
      delete current.credentialKinds[itemId]
      delete current.fillPolicies[itemId]
      delete current.plaintextReadPolicies[itemId]
      return json({ ok: true, itemId, demo: true })
    }
    if (url.pathname === '/api/fill/read-policy' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const itemId = await demoItemIdByName(String(body.item ?? ''))
      if (!itemId) return fail('item not found', 404)
      if (current.credentialKinds[itemId] === 'web') return fail('website credentials are fill-only', 400)
      if (current.credentialKinds[itemId] !== 'api') return fail('classify the credential as api first', 400)
      if (body.allow === true) current.plaintextReadPolicies[itemId] = { itemId, accountId: DEMO_EMAIL, expiresAt: Date.now() + 30 * 86400e3, createdAt: nowIso() }
      else delete current.plaintextReadPolicies[itemId]
      return json({ ok: true, itemId, allow: body.allow === true, demo: true })
    }
    if (url.pathname === '/api/grants/share' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const name = String(body.name ?? '')
      const agents = Array.isArray(body.agents) ? body.agents.map(String) : []
      if (!name || !agents.length) return fail('name and agents required', 400)
      const itemId = await demoItemIdByName(name)
      const seconds = Math.max(0, Number(body.seconds) || 0)
      for (const agent of agents) {
        current.grants[agent + '\u0000' + name] = {
          agent, name, mode: 'share', createdAt: nowIso(),
          expiresAt: seconds ? Date.now() + seconds * 1000 : 0, reads: 0,
          maxReads: body.maxReads ? Number(body.maxReads) : null, revokedAt: null, account: DEMO_EMAIL, itemId,
        }
      }
      current.demoWrites.push({ at: nowIso(), what: 'share', item: name, agents })
      return json({ ok: true, granted: agents.map((agent) => ({ agent, name })), errors: [], demo: true })
    }
    if (url.pathname === '/api/grants/update' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const grant = current.grants[String(body.agent ?? '') + '\u0000' + String(body.name ?? '')]
      if (!grant) return fail('grant not found', 404)
      if (typeof body.seconds === 'number') grant.expiresAt = body.seconds > 0 ? Date.now() + body.seconds * 1000 : 0
      if (body.maxReads != null) grant.maxReads = Math.max(1, Number(body.maxReads) || 1)
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/grants/revoke' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const grant = current.grants[String(body.agent ?? '') + '\u0000' + String(body.name ?? '')]
      if (!grant) return fail('grant not found', 404)
      grant.revokedAt = nowIso()
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/grants/restore' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const grant = current.grants[String(body.agent ?? '') + '\u0000' + String(body.name ?? '')]
      if (!grant) return fail('grant not found', 404)
      grant.revokedAt = null
      if (grant.expiresAt && grant.expiresAt <= Date.now()) grant.expiresAt = 0
      grant.reads = 0
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/grants/delete' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const key = String(body.agent ?? '') + '\u0000' + String(body.name ?? '')
      if (!current.grants[key]) return fail('grant not found', 404)
      delete current.grants[key]
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/policies' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const name = String(body.name ?? '')
      if (!name) return fail('name required', 400)
      current.policies[name] = { noApproval: body.noApproval === true }
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/items/create' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const name = String(body.name ?? '').trim()
      if (!name) return fail('name required', 400)
      const vault = await demoVault()
      if (vault.seed.some((entry) => entry.name === name)) return fail('item already exists', 409)
      vault.seed.push({ name, group: String(body.group ?? ''), url: String(body.url ?? ''), username: String(body.username ?? ''), value: String(body.value ?? ''), notes: String(body.notes ?? ''), kind: null })
      vault.ciphers.push({
        id: 'demo-item-' + vault.ciphers.length + '-new', user_id: 'demo-user-1', type: 1, folder_id: null,
        name: await encryptStr(name, DEMO_USER_KEY.slice(0, 32), DEMO_USER_KEY.slice(32, 64)),
        notes: body.notes ? await encryptStr(String(body.notes), DEMO_USER_KEY.slice(0, 32), DEMO_USER_KEY.slice(32, 64)) : '',
        data: JSON.stringify({ login: { username: body.username ? await encryptStr(String(body.username), DEMO_USER_KEY.slice(0, 32), DEMO_USER_KEY.slice(32, 64)) : '', password: await encryptStr(String(body.value ?? ''), DEMO_USER_KEY.slice(0, 32), DEMO_USER_KEY.slice(32, 64)), totp: '', uris: [] }, fields: [] }),
        key: null, created_at: nowIso(), updated_at: nowIso(), deleted_at: null, archived_at: null,
        demo: { kind: null, readAllowed: false, origins: [], actions: [] },
      })
      current.itemIds[name] = vault.ciphers[vault.ciphers.length - 1].id
      current.demoWrites.push({ at: nowIso(), what: 'create', item: name })
      return json({ ok: true, created: true, demo: true })
    }
    if (url.pathname === '/api/items/delete' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const name = String(body.name ?? '')
      const vault = await demoVault()
      const index = vault.seed.findIndex((entry) => entry.name === name)
      if (index < 0) return fail('item not found', 404)
      vault.seed.splice(index, 1)
      vault.ciphers.splice(index, 1)
      delete current.itemIds[name]
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/items/update' && request.method === 'POST') {
      // The demo accepts the call so the dialog's save path is exercised, but it
      // does not rewrite the encrypted rows: that would need a persistent store
      // and the demo deliberately has none.
      const body = await request.json().catch(() => ({}))
      const current = await demoState()
      if (body.expiresAt !== undefined) current.demoWrites.push({ at: nowIso(), what: 'expiry', item: String(body.name ?? ''), value: body.expiresAt })
      return json({ ok: true, demo: true, note: 'demo: 修改已记录，但不会持久化' })
    }
    if (url.pathname === '/api/agents/update' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const agent = current.agents[String(body.name ?? '')]
      if (!agent) return fail('agent not found', 404)
      if (typeof body.alias === 'string') agent.alias = body.alias
      if (typeof body.note === 'string') agent.note = body.note
      if (typeof body.write === 'boolean') agent.write = body.write
      if (Array.isArray(body.allow)) agent.allow = body.allow.map(String)
      if (typeof body.allowAll === 'boolean') agent.allowAll = body.allowAll
      current.demoWrites.push({ at: nowIso(), what: 'agent', name: agent.name })
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/notify/test' && request.method === 'POST') return json({ ok: true, demo: true, results: { demo: '演示模式不会真的发送通知' } })

    // Anything not modelled here answers honestly instead of 404-ing a page.
    if (url.pathname.startsWith('/api/')) return json({ ok: true, demo: true, note: '这个接口在演示里是空实现' })
    return fail('not found', 404)
  },
}

function loginPage() {
  return String.raw`<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · Secrets Broker 演示</title>
<style>
:root{--bg:#f3f6fb;--card:#fff;--line:#e3e9f2;--text:#152033;--muted:#6b7890;--ok:#0f9d8a}
*{box-sizing:border-box}
body{font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px}
.card{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:28px;box-shadow:0 8px 24px rgba(20,40,80,.06)}
h1{font-size:19px;margin:0 0 4px}
.sub{color:var(--muted);font-size:12px;margin:0 0 18px}
.demo{background:#fff7e6;border:1px solid #f5d9ae;color:#8a5a00;border-radius:10px;padding:10px 12px;font-size:12px;margin-bottom:16px;line-height:1.7}
.demo code{background:rgba(0,0,0,.06);padding:1px 5px;border-radius:4px;font-size:12px}
label{display:block;font-size:12px;color:var(--muted);margin:12px 0 5px}
input{width:100%;border:1px solid #d8e0ec;border-radius:11px;padding:11px 12px;font:inherit;outline:none}
input:focus{border-color:var(--ok);box-shadow:0 0 0 3px rgba(15,157,138,.14)}
button{width:100%;margin-top:18px;border:0;border-radius:11px;padding:11px;font:inherit;font-weight:600;background:var(--ok);color:#fff;cursor:pointer}
.status{font-size:12px;min-height:18px;margin-top:10px;color:#c0392b}
</style></head><body>
<div class="card">
  <h1>Secrets Broker · 演示</h1>
  <p class="sub">这是公开演示，数据全部是虚拟的。</p>
  <div class="demo">
    管理密码：<code>demo</code><br>
    解锁主密码：<code>demo-master-password</code><br>
    <span style="opacity:.8">没有真实 Nodewarden，没有任何真实密钥。</span>
  </div>
  <label for="password">管理密码</label>
  <input id="password" type="password" value="demo" autocomplete="current-password">
  <button id="go">进入演示</button>
  <div id="status" class="status"></div>
</div>
<script>
  const go = document.getElementById('go')
  async function submit() {
    const status = document.getElementById('status')
    status.textContent = ''
    try {
      const response = await fetch('/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: document.getElementById('password').value }) })
      const data = await response.json()
      if (!response.ok) { status.textContent = data.error || '登录失败'; return }
      location.href = '/'
    } catch (error) { status.textContent = String(error.message || error) }
  }
  go.onclick = submit
  document.getElementById('password').addEventListener('keydown', (event) => { if (event.key === 'Enter') submit() })
</script></body></html>`
}
