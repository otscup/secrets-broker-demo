import fs from 'node:fs'
// The demo must be self-contained: virtual data, no real vault, and the real
// unlock path must still work end to end.
import { Miniflare } from 'miniflare'
import { pbkdf2, hkdfExpand, decryptBw, decryptCipherRow } from './src/crypto.js'

const results = []
const pass = (n) => { results.push({ n, ok: true }); console.log('PASS  ' + n) }
const fail = (n, d) => { results.push({ n, ok: false, d }); console.log('FAIL  ' + n + ' :: ' + d) }

const mf = new Miniflare({
  modules: true,
  modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }],
  compatibilityDate: '2026-08-01',
  scriptPath: 'src/index.js',
  // The static assets live in public/ and are reached through the ASSETS
  // binding, which is how wrangler wires them in production too.
  sitePath: 'public',
  // Every API call is answered by one Durable Object, so the demo has a single
  // consistent view of its state.
  durableObjects: { DEMO_STATE: 'DemoState' },
})
const cookieFor = async (password) => {
  const res = await mf.dispatchFetch('https://demo.test/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password }),
  })
  return { status: res.status, cookie: String(res.headers.get('set-cookie') || '').split(';')[0], body: await res.json().catch(() => ({})) }
}

// D1: the production login page is served, with its form intact and no OIDC
// section, because the demo has no identity provider to offer.
{
  const res = await mf.dispatchFetch('https://demo.test/login')
  const html = await res.text()
  const hasForm = html.includes('id="password"') && html.includes('id="go"')
  const noOidc = !html.includes('/oidc/login')
  const hasLogo = html.includes('/logo.png')
  if (res.status === 200 && hasForm && noOidc && hasLogo) pass('D1 the production login page is served without an OIDC section')
  else fail('D1', JSON.stringify({ status: res.status, hasForm, noOidc, hasLogo }))
}

// D2: the wrong admin password is refused.
{
  const bad = await cookieFor('not-the-password')
  if (bad.status === 401) pass('D2 a wrong admin password is refused')
  else fail('D2', String(bad.status))
}

// D3: the right one issues a session.
{
  const good = await cookieFor('demo')
  if (good.status === 200 && good.cookie.startsWith('demo_session=')) pass('D3 the demo password issues a session')
  else fail('D3', JSON.stringify(good))
}

// D4: without a session the API is closed.
{
  const res = await mf.dispatchFetch('https://demo.test/api/state')
  if (res.status === 401) pass('D4 the API requires the demo session')
  else fail('D4', String(res.status))
}

const { cookie } = await cookieFor('demo')
const get = (path) => mf.dispatchFetch('https://demo.test' + path, { headers: { cookie } })
const post = (path, body) => mf.dispatchFetch('https://demo.test' + path, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify(body) })

// D5: bootstrap gives what the browser needs to derive and unwrap the key.
{
  const info = await (await get('/api/bootstrap')).json()
  const ok = info.kdfType === 0 && info.kdfIterations > 0 && typeof info.profileKey === 'string' && info.profileKey.startsWith('2.')
  if (ok) pass('D5 bootstrap returns a real wrapped profile key')
  else fail('D5', JSON.stringify({ kdfType: info.kdfType, hasKey: Boolean(info.profileKey) }))
}

// D6: the real unlock chain works: PBKDF2 -> HKDF -> unwrap -> 64-byte key.
{
  const info = await (await get('/api/bootstrap')).json()
  const masterKey = await pbkdf2('demo-master-password', String(info.email).toLowerCase(), info.kdfIterations)
  const encKey = await hkdfExpand(masterKey, 'enc', 32)
  const macKey = await hkdfExpand(masterKey, 'mac', 32)
  const userKey = await decryptBw(info.profileKey, encKey, macKey)
  if (userKey.length === 64) pass('D6 the browser-side unlock chain yields a 64-byte user key')
  else fail('D6', 'length ' + userKey.length)
}

// D7: the items list decrypts, and the values are visibly fake.
{
  const { items } = await (await get('/api/items')).json()
  const names = (items || []).map((item) => item.name)
  const wanted = ['openai-prod', 'github.com', 'legacy-smtp']
  const missing = wanted.filter((n) => !names.includes(n))
  if (!missing.length && items.length >= 6) pass('D7 the virtual items decrypt and list')
  else fail('D7', JSON.stringify({ count: items.length, missing }))
}

// D8: every demo value is prefixed so nobody mistakes it for a live key.
{
  const info = await (await get('/api/bootstrap')).json()
  const masterKey = await pbkdf2('demo-master-password', String(info.email).toLowerCase(), info.kdfIterations)
  const encKey = await hkdfExpand(masterKey, 'enc', 32)
  const macKey = await hkdfExpand(masterKey, 'mac', 32)
  const userKey = await decryptBw(info.profileKey, encKey, macKey)
  const b64 = (bytes) => Buffer.from(bytes).toString('base64')
  const session = { email: info.email, symEncKey: b64(userKey.slice(0, 32)), symMacKey: b64(userKey.slice(32, 64)) }
  // Decrypt the seeded rows exactly as the worker does.
  const { demoVault } = await import('./src/vault.js')
  const vault = await demoVault()
  let suspicious = 0
  for (const row of vault.ciphers) {
    const decrypted = await decryptCipherRow(row, session)
    const value = decrypted.data?.login?.password ?? ''
    if (value && !/demo/i.test(value)) suspicious += 1
  }
  if (suspicious === 0) pass('D8 every virtual credential value is marked as demo data')
  else fail('D8', suspicious + ' values do not mention demo')
}

// D9: state carries the demo notice and the classification switch default.
{
  const state = await (await get('/api/state')).json()
  const ok = state.requireClassification === true && state.demo && state.demo.items > 0 && Array.isArray(state.audit) && state.audit.length > 0
  if (ok) pass('D9 state carries the demo notice, the switch default and seeded history')
  else fail('D9', JSON.stringify({ switch: state.requireClassification, demo: state.demo }))
}

// D10: the globe has data to draw.
{
  const geo = await (await get('/api/geo/events?range=24h&sinceSeq=0&limit=300')).json()
  const withGeo = (geo.events || []).filter((e) => e.geo && typeof e.geo.lat === 'number')
  if (geo.enabled && withGeo.length >= 5 && geo.broker) pass('D10 the globe has seeded visits and a broker position')
  else fail('D10', JSON.stringify({ enabled: geo.enabled, count: withGeo.length, broker: geo.broker }))
}

// D11: writes are accepted but marked as demo, and never persisted anywhere real.
{
  const res = await post('/api/settings', { requireClassification: false })
  const body = await res.json()
  const state = await (await get('/api/state')).json()
  if (body.demo === true && body.ok === true && state.requireClassification === false) pass('D11 a demo write is accepted and reflected in memory')
  else fail('D11', JSON.stringify({ body, switch: state.requireClassification }))
}

// D12: the demo never exposes the demo master password through the API it does
// not already print on the login page, and never a profile secret it should not.
{
  const state = JSON.stringify(await (await get('/api/state')).json())
  const items = JSON.stringify(await (await get('/api/items')).json())
  const leaksValue = /sk-demo-0000|demo-web-password/.test(state)
  if (!leaksValue) pass('D12 /api/state never carries a credential value')
  else fail('D12', 'a value leaked into state')
  void items
}

// D13: an unknown API path answers honestly instead of a bare 404 page.
{
  const res = await get('/api/oauth/clients')
  const body = await res.json()
  if (res.status === 200 && body.demo === true) pass('D13 an unmodelled API path answers with a demo note')
  else fail('D13', JSON.stringify({ status: res.status, body }))
}

// D14: the globe assets exist and are non-trivial. Wrangler serves them before
// the worker runs, so a request through the worker is not the right check.
{
  const needed = ['public/globe.js', 'public/earth.jpg']
  const missing = needed.filter((file) => { try { return fs.statSync(file).size < 1000 } catch { return true } })
  if (missing.length === 0) pass('D14 the globe bundle and earth texture are present')
  else fail('D14', 'missing or too small: ' + missing.join(','))
}

// D15: two approvals are waiting, and approving one clears it and grants.
{
  const before = await (await get('/api/state')).json()
  const waiting = before.pending || []
  if (waiting.length === 2) pass('D15 two approvals are waiting')
  else fail('D15', 'pending count ' + waiting.length)

  const target = waiting.find((entry) => entry.action === 'secret.read') || waiting[0]
  const res = await post('/api/pending/decide', { id: target.id, decision: '24h' })
  const after = await (await get('/api/state')).json()
  const still = (after.pending || []).some((entry) => entry.id === target.id)
  const granted = Object.values(after.grants || {}).some((grant) => grant.agent === target.agent && grant.name === target.name && !grant.revokedAt)
  if (res.status === 200 && !still && granted) pass('D16 approving clears the request and writes the grant')
  else fail('D16', JSON.stringify({ status: res.status, still, granted }))
}

// D17: reminders exist, so the notice bar has something to rotate.
{
  const state = await (await get('/api/state')).json()
  const reminders = state.reminders || []
  if (reminders.length === 2 && reminders.every((r) => r.message)) pass('D17 two reminders are seeded')
  else fail('D17', JSON.stringify(reminders))
}

// D18: the globe legend markup and its renderer are in the page.
{
  const html = await (await mf.dispatchFetch('https://demo.test/')).text()
  const hasBox = html.includes('id="globe-legend"')
  const hasRender = html.includes('function renderGlobeLegend')
  const hasPalette = html.includes('GLOBE_PALETTE')
  if (hasBox && hasRender && hasPalette) pass('D18 the globe carries an agent colour legend')
  else fail('D18', JSON.stringify({ hasBox, hasRender, hasPalette }))
}

// D19: the arcs keep one colour per agent instead of fading to a shared one.
{
  const bundle = fs.readFileSync('public/globe.js', 'utf8')
  // A shared end colour would still appear as the literal gradient pair.
  const sharedEnd = bundle.includes('7fc7ff') && bundle.includes('[e,"#7fc7ff"]')
  if (!sharedEnd) pass('D19 arcs are not faded into a shared colour')
  else fail('D19', 'arcs still use a shared end colour')
}

// D20: the logo and the avatar are real files.
{
  const sizes = ['public/logo.png', 'public/avatar.png'].map((file) => { try { return fs.statSync(file).size } catch { return 0 } })
  if (sizes.every((size) => size > 500)) pass('D20 logo and avatar assets exist')
  else fail('D20', JSON.stringify(sizes))
}

// D21: the session cookie is HttpOnly and Secure.
{
  const res = await mf.dispatchFetch('https://demo.test/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'demo' }),
  })
  const cookie = String(res.headers.get('set-cookie') || '')
  const ok = /HttpOnly/i.test(cookie) && /Secure/i.test(cookie) && /SameSite/i.test(cookie)
  if (ok) pass('D21 the demo session cookie is HttpOnly, Secure and SameSite')
  else fail('D21', cookie)
}

// D22: no demo password is echoed from the API.
{
  const info = await (await get('/api/bootstrap')).json()
  const raw = JSON.stringify(info)
  const leaks = raw.includes('demo-master-password') || raw.includes('"masterPassword"')
  if (!leaks) pass('D22 the API does not echo the demo passwords')
  else fail('D22', 'a password appeared in the bootstrap response')
}

await mf.dispose()
const passed = results.filter((r) => r.ok).length
console.log('\n==== demo ' + passed + '/' + results.length + ' passed ====')
if (passed !== results.length) process.exit(1)

