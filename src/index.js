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
  demoVault, demoItemIdByName, DEMO_EMAIL,
  DEMO_KDF_ITERATIONS, DEMO_USER_KEY, DEMO_PENDING, DEMO_REMINDERS, demoSeedFingerprint,
} from './vault.js'
import { decryptCipherRow, extractSecret, extractUsername, extractTotp, encryptStr, bytesToB64 } from './crypto.js'
import { parseJwt, verifyJwtSignature, validateIdTokenClaims, checkUserinfoSub } from './oidc.js'
import {
  issuerFor, DEMO_CLIENT_ID, DEMO_CLIENT_SECRET,
  discoveryDocument, jwksDocument, authorizePage, authorize, token as idpToken, userinfo, setCodeStore,
} from './idp.js'

// The visitor's origin. The Worker stamps it on the forwarded request because the
// Durable Object only ever sees the script's own hostname.
const originOf = (request) => request.headers.get('x-demo-origin') || issuerFor(request)

const DEMO_ADMIN_PASSWORD = 'demo'
const SESSION_COOKIE = 'demo_session'

const encoder = new TextEncoder()
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
})
const fail = (message, status = 400) => json({ error: message }, status)
const htmlResponse = (body, status = 200) => new Response(body, {
  status,
  headers: {
    'content-type': 'text/html; charset=utf-8',
    // No-store plus must-revalidate: the login page is the one place where a
    // stale copy silently shows a door that no longer exists.
    'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
    pragma: 'no-cache',
    expires: '0',
  },
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

const sessionCookie = (id) => `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`

// ── Demo state ──────────────────────────────────────────────────────────────
// Mutable in-memory state derived from the virtual vault. Reset whenever the
// isolate restarts, which is the intended behaviour for a demo.
let state = null
// How long a visitor's changes survive before the demo looks new again. Short
// enough that a stranger sees the seeded state, long enough to click around.
const DEMO_RESET_AFTER_MS = 30 * 60 * 1000

// The seed's own digest, so editing src/vault.js resets the demo without anyone
// remembering to bump a constant. A hand-kept version is exactly the thing that
// gets forgotten, and forgetting means serving stale state after a deploy.
async function demoState() {
  const version = 'seed-' + (await demoSeedFingerprint())
  // Reset for either reason: a different seed, or an old session. Both keep the
  // demo showing what src/vault.js says it shows.
  if (state && (state.__version !== version || Date.now() - (state.__touchedAt ?? 0) > DEMO_RESET_AFTER_MS)) {
    state = null
  }
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
    // Two approvals waiting, so the notice bar and the pending table have
    // something to show and the approve buttons can be tried.
    pending: Object.fromEntries(DEMO_PENDING.map((entry) => [entry.id, { ...entry }])),
    reminders: DEMO_REMINDERS.map((entry) => ({ ...entry })),
    audit,
    itemIds: Object.fromEntries(vault.seed.map((entry, i) => [entry.name, 'demo-item-' + (i + 1)])),
    credentialKinds, fillPolicies, plaintextReadPolicies,
    policies: {},
    settings: { vaultEmail: DEMO_EMAIL, notifications: {}, requireClassification: true, siteName: 'Secrets Broker' },
    profile: { name: 'Demo User', email: DEMO_EMAIL, avatarUrl: '/avatar.png' },
    demoWrites: [],
    __version: 'seed-' + (await demoSeedFingerprint()),
    __touchedAt: Date.now(),
  }
  return state
}

// Any write pushes the reset window out, so an actively used demo does not reset
// mid-click.
function touchState(current) {
  if (current) current.__touchedAt = Date.now()
  return current
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
    // The demo passwords are published on the login page, not here: an API
    // response ends up in logs, proxies and devtools screenshots far more often
    // than a page a visitor reads once.
    demo: true,
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

// Deterministic PRNG (mulberry32) so the same range renders the same chart
// until the hour rolls over.
function demoSeed(text) {
  let seed = 0
  for (let i = 0; i < text.length; i += 1) seed = (seed * 31 + text.charCodeAt(i)) >>> 0
  return seed || 1
}

function demoRandom(seedText) {
  let a = demoSeed(seedText)
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// Replace the counts a fresh demo vault cannot have produced yet, keeping the
// real numbers for pending/activeGrants — those come from what the visitor
// actually approved while clicking around.
function demoStatsShape(stats, range, items, agents) {
  const rand = demoRandom(range + ':' + new Date().toISOString().slice(0, 13))
  const hourWeight = (index, count) => {
    // A working day: quiet at night, a morning ramp and an afternoon peak.
    const hour = range === '24h' ? index : (index % 24)
    const shape = [1, 1, 1, 1, 1, 2, 3, 5, 8, 11, 13, 12, 9, 8, 10, 12, 14, 13, 10, 7, 5, 3, 2, 1][hour % 24]
    return Math.max(0, Math.round(shape * (count || 1) * (0.55 + rand() * 0.9)))
  }
  const buckets = (stats.buckets || []).map((bucket, index) => ({ label: bucket.label, count: hourWeight(index, 1) }))
  const totalReads = buckets.reduce((sum, bucket) => sum + bucket.count, 0)
  const names = items.map((item) => item.name)
  const pick = (list, n) => list.slice().sort(() => rand() - 0.5).slice(0, n)
  const topItems = pick(names, Math.min(5, names.length)).map((name) => ({ name, count: Math.max(1, Math.round(totalReads * (0.05 + rand() * 0.2))) }))
    .sort((a, b) => b.count - a.count)
  const agentNames = agents.map((agent) => agent.name)
  const weights = agentNames.map(() => 0.3 + rand())
  const weightSum = weights.reduce((sum, w) => sum + w, 0) || 1
  const topAgents = agentNames.map((name, index) => ({ name, count: Math.max(1, Math.round(totalReads * weights[index] / weightSum)) }))
    .sort((a, b) => b.count - a.count)
  return { ...stats, buckets, totalReads, topItems, topAgents, activeAgents: agentNames.length || stats.activeAgents }
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
    reminders: current.reminders ?? [],
    stats: statsFor(current, '24h'),
    demo: { writes: current.demoWrites.length, items: items.length },
  }
}

// ── Router ──────────────────────────────────────────────────────────────────
// ── Routes ──────────────────────────────────────────────────────────────────
// Pages are served here; every API call goes through one Durable Object so the
// demo has a single consistent view. Without that each isolate kept its own copy
// of the state, so approving a request on one left another still showing it.
export class DemoState {
  constructor(ctx, env) {
    this.ctx = ctx
    this.env = env
    // The IdP issues codes through this object, so a code survives being
    // redeemed on a different isolate than the one that created it.
    setCodeStore({
      set: (code, record) => { idpCodes.set(code, record) },
      take: (code) => {
        const found = idpCodes.get(code)
        idpCodes.delete(code)
        return found
      },
    })
  }

  async fetch(request) {
    return handleApi(request, this.env)
  }
}

// Authorization codes, held by the single state object.
const idpCodes = new Map()

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    if (url.pathname === '/' || url.pathname === '/index.html') {
      // Without a session the console would load and then fail every request, so
      // send the visitor to the one door.
      if (!readCookie(request, SESSION_COOKIE)) return Response.redirect(new URL('/login', url).toString(), 302)
      return htmlResponse(uiHtml)
    }
    if (url.pathname === '/login') return htmlResponse(demoLoginPage())

    // ── The demo's own OpenID Provider ──────────────────────────────────────
    // Discovery and JWKS are stateless, so they answer without waking the state
    // object. Everything that touches an authorization code runs inside it, or
    // the code would be written in one place and looked up in another.
    if (url.pathname === '/.well-known/openid-configuration') return json(discoveryDocument(issuerFor(request)))
    if (url.pathname === '/idp/jwks') return json(jwksDocument())
    // API, the broker's OIDC endpoints and the stateful IdP endpoints all share
    // one state object.
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/oidc/') || url.pathname === '/idp/authorize' || url.pathname === '/idp/token' || url.pathname === '/idp/userinfo') {
      // The origin the visitor used. The object cannot see it: the stub request
      // carries the script's own hostname, so pass it explicitly.
      const forwarded = new Request(request)
      forwarded.headers.set('x-demo-origin', issuerFor(request))
      const stub = env.DEMO_STATE.get(env.DEMO_STATE.idFromName('demo'))
      return stub.fetch(forwarded)
    }
    return fail('not found', 404)
  },
}


// ── OIDC: the broker side ───────────────────────────────────────────────────
// The demo's IdP is a normal provider from here down: discovery, PKCE S256,
// a signed state cookie, nonce, JWKS signature verification and full claim
// validation via src/oidc.js, unchanged from production.

const OIDC_STATE_COOKIE = 'demo_oidc_state'
const oidcUsedStates = new Map()

function oidcStatus(request) {
  const issuer = originOf(request)
  return json({ enabled: true, providers: [{ id: 'demo', label: '演示账号', issuer }], issuer })
}

function b64urlEncodeBytes(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const oidcStateCookie = (payload) => OIDC_STATE_COOKIE + '=' + encodeURIComponent(payload) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600'

async function oidcLogin(request, env) {
  const url = new URL(request.url)
  // The host the sign-in starts on. Recorded in the state cookie so the callback
  // knows which issuer to expect, even behind a proxy.
  const origin = originOf(request)
  // Everything the sign-in needs, carried in the state cookie so the callback
  // does not trust anything the provider echoes back.
  const state = crypto.randomUUID()
  const verifier = b64urlEncodeBytes(crypto.getRandomValues(new Uint8Array(32)))
  const challenge = b64urlEncodeBytes(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  const nonce = crypto.randomUUID()
  const next = url.searchParams.get('next') === 'profile' ? 'profile' : ''
  const payload = JSON.stringify({ state, verifier, nonce, next, issuer: origin, expires: Date.now() + 10 * 60 * 1000 })

  const target = new URL(origin + '/idp/authorize')
  target.searchParams.set('client_id', DEMO_CLIENT_ID)
  target.searchParams.set('redirect_uri', origin + '/oidc/callback')
  target.searchParams.set('response_type', 'code')
  target.searchParams.set('scope', 'openid profile email')
  target.searchParams.set('state', state)
  target.searchParams.set('code_challenge', challenge)
  target.searchParams.set('code_challenge_method', 'S256')
  target.searchParams.set('nonce', nonce)
  return new Response(null, {
    status: 302,
    headers: { location: target.toString(), 'set-cookie': oidcStateCookie(payload) },
  })
}

async function oidcCallback(request, env) {
  const url = new URL(request.url)
  const clearCookie = OIDC_STATE_COOKIE + '=; Path=/; Max-Age=0'
  const failOidc = (message, status = 400) => json({ error: message }, status, { 'set-cookie': clearCookie })

  const raw = (() => {
    try { return decodeURIComponent(readCookie(request, OIDC_STATE_COOKIE)) } catch { return '' }
  })()
  if (!raw) return failOidc('OIDC state missing: start the sign-in again', 400)
  let saved = null
  try { saved = JSON.parse(raw) } catch { return failOidc('OIDC state unreadable', 400) }
  if (saved.expires < Date.now()) return failOidc('OIDC state expired, start again', 400)
  // Single use: taken before anything else can fail, so a replay cannot retry.
  if (oidcUsedStates.has(saved.state)) return failOidc('OIDC state already used (replay)', 400)
  oidcUsedStates.set(saved.state, Date.now())
  for (const [key, at] of oidcUsedStates) if (Date.now() - at > 15 * 60 * 1000) oidcUsedStates.delete(key)

  if (String(url.searchParams.get('state') ?? '') !== saved.state) return failOidc('OIDC state mismatch', 400)
  const error = url.searchParams.get('error')
  if (error) return failOidc('the provider returned "' + error + '": ' + (url.searchParams.get('error_description') ?? ''), 403)
  const code = url.searchParams.get('code')
  if (!code) return failOidc('missing authorization code', 400)

  try {
    // The IdP and the broker are the same worker, so this dispatches straight to
    // the handler. A real provider would need a network call here; here one would
    // only dial out to our own host, and fail offline.
    const expectedIssuerForToken = String(saved.issuer || originOf(request))
    const tokenResponse = await idpToken(new Request(expectedIssuerForToken + '/idp/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: String(saved.issuer || originOf(request)) + '/oidc/callback',
        client_id: DEMO_CLIENT_ID,
        client_secret: DEMO_CLIENT_SECRET,
        code_verifier: saved.verifier,
      }),
    }))
    const tokens = await tokenResponse.json()
    if (!tokenResponse.ok || !tokens.id_token) return failOidc(tokens.error_description ?? 'token exchange failed', 502)

    // Signature verification runs for real against the provider's published JWKS.
    const parsed = parseJwt(tokens.id_token)
    await verifyJwtSignature(parsed, jwksDocument())
    // Then the claims: issuer, audience, expiry, nonce, subject.
    // The issuer the sign-in began on. Falling back to the callback request's
    // origin would break behind a proxy, or whenever the two hosts differ.
    const expectedIssuer = String(saved.issuer || originOf(request))
    validateIdTokenClaims(parsed.payload, { issuer: expectedIssuer, clientId: DEMO_CLIENT_ID, nonce: saved.nonce })

    const user = await userinfo(expectedIssuer).json()
    checkUserinfoSub(user.sub, parsed.payload.sub)

    // Signed in: issue the demo session, the same one the password login makes.
    const id = crypto.randomUUID()
    sessions.set(id, { id, expiresAt: Date.now() + 3600e3, ...VAULT_KEYS })
    const state = await demoState()
    state.profile = {
      name: String(user.name ?? 'Demo User'),
      email: String(user.email ?? ''),
      avatarUrl: String(user.picture ?? '/avatar.png'),
      oidcSub: String(parsed.payload.sub),
    }
    state.demoWrites.push({ at: nowIso(), what: 'oidc-login', sub: parsed.payload.sub })

    const headers = new Headers({ location: saved.next === 'profile' ? '/#profile' : '/' })
    headers.append('set-cookie', sessionCookie(id))
    headers.append('set-cookie', clearCookie)
    return new Response(null, { status: 302, headers })
  } catch (error) {
    return failOidc(String((error && error.message) || error), 502)
  }
}

// Everything the pages call. Runs inside the Durable Object.
async function handleApi(request, env) {
  const url = new URL(request.url)
  // The IdP's stateful half, served inside the object that owns the codes.
  if (url.pathname === '/idp/userinfo') return userinfo(originOf(request))
  if (url.pathname === '/idp/authorize') {
    if (request.method === 'POST') return authorize(request)
    return htmlResponse(authorizePage({
      clientId: url.searchParams.get('client_id') ?? '',
      redirectUri: url.searchParams.get('redirect_uri') ?? '',
      state: url.searchParams.get('state') ?? '',
      codeChallenge: url.searchParams.get('code_challenge') ?? '',
      nonce: url.searchParams.get('nonce') ?? '',
      scope: url.searchParams.get('scope') ?? '',
    }))
  }
  if (url.pathname === '/idp/token' && request.method === 'POST') return idpToken(request)

  if (url.pathname === '/api/oidc/status') return oidcStatus(request)
  if (url.pathname === '/api/oidc/login' || url.pathname === '/oidc/login') return oidcLogin(request, env)
  if (url.pathname === '/oidc/callback') return oidcCallback(request, env)
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
        email: DEMO_EMAIL, name: current.profile.name, avatarUrl: '/avatar.png',
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
      const range = url.searchParams.get('range') ?? '24h'
      return json(demoStatsShape(statsFor(current, range), range, await listItems(session), Object.values(current.agents ?? {})))
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
touchState(current)
        current.demoWrites.push({ at: nowIso(), what: 'requireClassification', value: body.requireClassification })
      }
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/security') return json({ passwordSource: 'demo', totpEnabled: false, totpPending: false })
    if (url.pathname === '/api/profile') return json({ profile: (await demoState()).profile, oidcEnabled: false, oidcProviders: [], oidcBindings: {} })
    if (url.pathname === '/api/sessions') return json({ sessions: [{ id: 'demo', ua: request.headers.get('user-agent') ?? '', ip: request.headers.get('cf-connecting-ip') ?? '', createdAt: nowIso(), lastSeen: nowIso(), current: true }] })
    if (url.pathname === '/api/oidc/status') return oidcStatus(request)
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
touchState(current)
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
touchState(current)
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
      touchState(current)
      if (typeof body.seconds === 'number') grant.expiresAt = body.seconds > 0 ? Date.now() + body.seconds * 1000 : 0
      if (body.maxReads != null) grant.maxReads = Math.max(1, Number(body.maxReads) || 1)
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/grants/revoke' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const grant = current.grants[String(body.agent ?? '') + '\u0000' + String(body.name ?? '')]
      if (!grant) return fail('grant not found', 404)
      touchState(current)
      grant.revokedAt = nowIso()
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/grants/restore' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const grant = current.grants[String(body.agent ?? '') + '\u0000' + String(body.name ?? '')]
      if (!grant) return fail('grant not found', 404)
      touchState(current)
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
touchState(current)
      return json({ ok: true, demo: true })
    }
    if (url.pathname === '/api/pending/decide' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const id = String(body.id ?? '')
      const request_ = current.pending[id]
      if (!request_) return fail('request not found', 404)
      delete current.pending[id]
touchState(current)
      const decision = String(body.decision ?? '')
      if (decision !== 'deny') {
        const seconds = decision === '1h' ? 3600 : decision === '24h' ? 86400 : decision === '7d' ? 7 * 86400 : 0
        const itemId = await demoItemIdByName(request_.name)
        current.grants[request_.agent + '\u0000' + request_.name] = {
          agent: request_.agent, name: request_.name, mode: decision, createdAt: nowIso(),
          expiresAt: seconds ? Date.now() + seconds * 1000 : 0, reads: 0,
          maxReads: decision === 'once' ? 1 : null, revokedAt: null, account: DEMO_EMAIL, itemId,
        }
      }
      current.demoWrites.push({ at: nowIso(), what: 'decide', id, decision })
      return json({ ok: true, demo: true, decision })
    }
    if (url.pathname === '/api/policies' && request.method === 'POST') {
      const current = await demoState()
      const body = await request.json().catch(() => ({}))
      const name = String(body.name ?? '')
      if (!name) return fail('name required', 400)
      current.policies[name] = { noApproval: body.noApproval === true }
touchState(current)
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
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
}
// The demo's only door: its OIDC provider.
//
// The production login page pairs a password form with the providers, because a
// real installation has a local admin password. The demo has no such thing to
// protect: its password is published. So this page offers the provider alone,
// and says what clicking it does.
function demoLoginPage() {
  return String.raw`<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="/favicon.ico">
<title>登录 · Secrets Broker 演示</title><style>
    :root{--bg-grouped:#F2F2F7;--card:#FFFFFF;--label:#000000;--label-2:rgba(60,60,67,.6);--label-3:rgba(60,60,67,.3);--separator:rgba(60,60,67,.29);--fill:rgba(118,118,128,.12);--blue:#007AFF;--green:#34C759;--orange:#FF9500;--red:#FF3B30;--purple:#AF52DE}
    @media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg-grouped:#000;--card:#1C1C1E;--label:#fff;--label-2:rgba(235,235,245,.6);--label-3:rgba(235,235,245,.3);--separator:rgba(84,84,88,.6);--fill:rgba(118,118,128,.24);--blue:#0A84FF;--green:#30D158;--orange:#FF9F0A;--red:#FF453A;--purple:#BF5AF2}}
    html[data-theme="dark"]{--bg-grouped:#000;--card:#1C1C1E;--label:#fff;--label-2:rgba(235,235,245,.6);--label-3:rgba(235,235,245,.3);--separator:rgba(84,84,88,.6);--fill:rgba(118,118,128,.24);--blue:#0A84FF;--green:#30D158;--orange:#FF9F0A;--red:#FF453A;--purple:#BF5AF2}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg-grouped);color:var(--label);font:17px/1.4 -apple-system,system-ui,"Segoe UI",sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}
    .card{width:100%;max-width:400px;background:var(--card);border-radius:16px;padding:28px 24px}
    .brand{display:flex;flex-direction:column;align-items:center;gap:10px;text-align:center;margin-bottom:22px}
    .brand img{width:64px;height:64px;border-radius:16px;object-fit:cover;display:block}
    h1{font-size:22px;line-height:28px;margin:0;letter-spacing:-.4px}
    .sub{color:var(--label-2);font-size:15px;margin:6px 0 0;text-align:center}
    .oidc{display:flex;align-items:center;justify-content:center;gap:8px;min-height:50px;text-decoration:none;font-size:17px;font-weight:600;color:#fff;background:var(--blue);border-radius:12px}
    .oidc:active{opacity:.85}
    .rows{margin:18px 0 0;border-top:1px solid var(--separator)}
    .row{display:flex;align-items:center;gap:10px;min-height:46px;padding:10px 0;border-bottom:1px solid var(--separator);font-size:15px;color:var(--label)}
    .row__label{color:var(--label-2);flex:0 0 auto;min-width:76px}
    .row__value{flex:1 1 auto;text-align:right;font-variant-numeric:tabular-nums}
    .dot{width:8px;height:8px;border-radius:50%;background:var(--green);flex:0 0 auto}
    .note{color:var(--label-2);font-size:13px;line-height:1.55;margin:18px 0 0}
    .note b{color:var(--label);font-weight:600}
    code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--fill);border-radius:5px;padding:1px 5px}
</style></head><body>
<div class="card">
  <div class="brand"><img src="/logo.png" alt=""><h1>Secrets Broker 演示</h1><p class="sub">数据全部是虚拟的，不连接任何真实密钥库。</p></div>
  <a class="oidc" href="/oidc/login?provider=demo">使用演示账号登录</a>
  <div class="rows">
    <div class="row"><span class="dot"></span><span class="row__label" style="min-width:0;color:var(--label)">演示身份提供者在线</span></div>
    <div class="row"><span class="row__label">协议</span><span class="row__value">OIDC · PKCE · ES256</span></div>
    <div class="row"><span class="row__label">口令</span><span class="row__value"><code>demo</code></span></div>
  </div>
  <p class="note">点击后由本站自带的身份提供者完成授权：PKCE + ES256 签名 + JWKS 验签，与生产版同一套校验。任何人都能登录，看到的是固定样本。<b>不要把真实密钥放进演示站。</b></p>
</div></body></html>`
}
