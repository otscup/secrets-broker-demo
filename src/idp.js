// A tiny, self-contained OpenID Provider, so the demo's OIDC login is a real
// authorization-code + PKCE round trip rather than a mock.
//
// Why a local IdP instead of pointing the demo at auth-cf:
//  - A public demo must not ask strangers to sign in with a real GitHub account.
//    That would collect real identities into a throwaway site.
//  - It would also mean a real client secret living in a public repo.
//
// So the demo is its own IdP. Nothing here is a security boundary: the signing
// key is in this file, and the "user" is a fixture. What is real is the protocol:
// discovery, JWKS, ES256-signed id_tokens, PKCE S256, state and nonce checks, and
// full claim validation on the broker side.

// The issuer is derived from the request host, so the demo works on any domain
// it is deployed to. A hardcoded one breaks the moment the name changes: the
// discovery document, the token exchange and the issuer claim would disagree.
export function issuerFor(request) {
  // The Host header is the name the visitor used. It matters behind a route,
  // where request.url holds the script's own hostname instead.
  const host = request.headers.get('host')
  const url = new URL(request.url)
  if (host && !/^(127\.0\.0\.1|localhost|0\.0\.0\.0)(:|$)/.test(host)) {
    return url.protocol + '//' + host
  }
  return url.origin
}
export const DEMO_CLIENT_ID = 'demo-broker-client'
export const DEMO_CLIENT_SECRET = 'demo-client-secret-not-a-real-secret'

// The demo identity. Every visitor who completes the round trip becomes this
// person, which is what makes the demo safe to expose.
export const DEMO_SUBJECT = 'demo-user-1'
export const DEMO_EMAIL = 'demo@secrets-broker.local'
export const DEMO_NAME = 'Demo User'

// ES256 signing key. Public on purpose: this key signs nothing that matters.
const SIGNING_JWK = {
  key_ops: ['sign'],
  ext: true,
  kty: 'EC',
  x: 'H8Ekax_uSUOkI5ZH8en7Mjl0eyYAGkh_IrOVQYujo_o',
  y: '1k2FtgPQNQ2qpjl8o8qg8AXRLW_Hay7fXiDWEW-UOXo',
  crv: 'P-256',
  d: '6D3Pjzek3XfhdxSjaMN2PASi6StCVm1mpONdTIpBUJg',
}
const PUBLIC_JWK = {
  kty: 'EC',
  x: SIGNING_JWK.x,
  y: SIGNING_JWK.y,
  crv: 'P-256',
  kid: 'demo-key-1',
  use: 'sig',
  alg: 'ES256',
}

const encoder = new TextEncoder()

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const b64urlText = (text) => b64url(encoder.encode(text))

async function signIdToken(claims) {
  const header = { alg: 'ES256', kid: 'demo-key-1', typ: 'JWT' }
  const signingInput = b64urlText(JSON.stringify(header)) + '.' + b64urlText(JSON.stringify(claims))
  const key = await crypto.subtle.importKey('jwk', SIGNING_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  // WebCrypto ECDSA returns the raw r||s pair, which is what JWS wants.
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(signingInput))
  return signingInput + '.' + b64url(signature)
}

// Authorization codes. The default map is only for direct handler tests: the
// worker installs a store backed by the Durable Object, because a code issued by
// one isolate must be redeemable by the one that handles the callback.
const fallbackCodes = new Map()
let codeStore = null

export function setCodeStore(store) {
  codeStore = store
}

const codesApi = {
  set(code, record) {
    if (codeStore) return codeStore.set(code, record)
    return fallbackCodes.set(code, record)
  },
  take(code) {
    if (codeStore) return codeStore.take(code)
    const found = fallbackCodes.get(code)
    fallbackCodes.delete(code)
    return found
  },
}

function randomToken(bytes = 24) {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)))
}

async function sha256Base64Url(text) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text))
  return b64url(digest)
}

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
})

export const discoveryDocument = (issuer) => ({
  issuer,
  authorization_endpoint: issuer + '/idp/authorize',
  token_endpoint: issuer + '/idp/token',
  userinfo_endpoint: issuer + '/idp/userinfo',
  jwks_uri: issuer + '/idp/jwks',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['ES256'],
  scopes_supported: ['openid', 'profile', 'email'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  code_challenge_methods_supported: ['S256'],
  claims_supported: ['iss', 'aud', 'sub', 'exp', 'iat', 'nonce', 'email', 'email_verified', 'name', 'picture'],
})

export const jwksDocument = () => ({ keys: [PUBLIC_JWK] })

// The authorize page. A real IdP would authenticate first; the demo shows a
// confirmation so the redirect is visible rather than silent, but it will let
// anyone through. That is stated on the page.
export function authorizePage({ clientId, redirectUri, state, codeChallenge, nonce, scope }) {
  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>演示身份提供者</title>
<style>
:root{--bg:#f3f6fb;--card:#fff;--line:#e3e9f2;--text:#152033;--muted:#6b7890;--ok:#0f9d8a}
*{box-sizing:border-box}
body{font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px}
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:28px;box-shadow:0 8px 24px rgba(20,40,80,.06)}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--muted);font-size:12px;margin:0 0 18px}
.demo{background:#fff7e6;border:1px solid #f5d9ae;color:#8a5a00;border-radius:10px;padding:10px 12px;font-size:12px;margin-bottom:16px}
.who{display:flex;align-items:center;gap:10px;border:1px solid var(--line);border-radius:12px;padding:10px;margin-bottom:16px}
.who img{width:34px;height:34px;border-radius:50%;object-fit:cover;display:block}
.who .name{font-weight:600}
.who .mail{color:var(--muted);font-size:12px}
.row{display:flex;gap:8px;margin-top:8px}
button{flex:1;border:0;border-radius:11px;padding:11px;font:inherit;font-weight:600;cursor:pointer}
.allow{background:var(--ok);color:#fff}
.deny{border:1px solid var(--line);background:var(--card);color:var(--text)}
code{background:rgba(0,0,0,.06);padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-all}
</style></head><body>
<div class="card">
  <h1>演示身份提供者</h1>
  <p class="sub">Secrets Broker 演示内置的 OIDC 服务商</p>
  <div class="demo">这是演示站自带的 IdP，不是真实的 GitHub 或公司账号。点「允许」会以南下的演示身份登录，任何人点都一样。</div>
  <div class="who">
    <img src="/avatar.png" alt="">
    <div><div class="name">${esc(DEMO_NAME)}</div><div class="mail">${esc(DEMO_EMAIL)}</div></div>
  </div>
  <p class="sub">应用 <code>${esc(clientId)}</code> 请求身份：
    scope <code>${esc(scope || 'openid profile email')}</code></p>
  <p class="sub">回调地址 <code>${esc(redirectUri)}</code></p>
  <form method="post" action="/idp/authorize">
    <input type="hidden" name="client_id" value="${esc(clientId)}">
    <input type="hidden" name="redirect_uri" value="${esc(redirectUri)}">
    <input type="hidden" name="state" value="${esc(state)}">
    <input type="hidden" name="code_challenge" value="${esc(codeChallenge)}">
    <input type="hidden" name="nonce" value="${esc(nonce)}">
    <input type="hidden" name="scope" value="${esc(scope)}">
    <div class="row"><button class="allow" name="decision" value="allow">允许</button><button class="deny" name="decision" value="deny">拒绝</button></div>
  </form>
</div></body></html>`
}

// POST /idp/authorize: issue a code and bounce back to the client.
export async function authorize(request) {
  const form = await request.formData().catch(() => null)
  if (!form) return new Response('bad request', { status: 400 })
  const decision = String(form.get('decision') ?? '')
  const redirectUri = String(form.get('redirect_uri') ?? '')
  const state = String(form.get('state') ?? '')
  if (!redirectUri) return new Response('redirect_uri required', { status: 400 })

  const target = new URL(redirectUri)
  if (decision !== 'allow') {
    target.searchParams.set('error', 'access_denied')
    target.searchParams.set('error_description', 'the demo user declined')
    if (state) target.searchParams.set('state', state)
    return new Response(null, { status: 302, headers: { location: target.toString() } })
  }

  const code = randomToken(32)
  await codesApi.set(code, {
    clientId: String(form.get('client_id') ?? ''),
    redirectUri,
    codeChallenge: String(form.get('code_challenge') ?? ''),
    nonce: String(form.get('nonce') ?? ''),
    scope: String(form.get('scope') ?? 'openid profile email'),
    expiresAt: Date.now() + 5 * 60 * 1000,
  })
  target.searchParams.set('code', code)
  if (state) target.searchParams.set('state', state)
  return new Response(null, { status: 302, headers: { location: target.toString() } })
}

// POST /idp/token: exchange the code for an EdDSA/ES256 id_token and an access token.
export async function token(request) {
  const form = await request.formData().catch(() => null)
  if (!form) return json({ error: 'invalid_request' }, 400)
  const code = String(form.get('code') ?? '')
  const verifier = String(form.get('code_verifier') ?? '')
  const redirectUri = String(form.get('redirect_uri') ?? '')
  const clientId = String(form.get('client_id') ?? '')
  const clientSecret = String(form.get('client_secret') ?? '')
  const grantType = String(form.get('grant_type') ?? '')

  if (grantType !== 'authorization_code') return json({ error: 'unsupported_grant_type' }, 400)
  if (clientId && clientId !== DEMO_CLIENT_ID) return json({ error: 'invalid_client' }, 401)
  // The demo accepts its published secret, or none for the public style. It is a
  // demo: the check exists so the flow is shaped like the real one.
  if (clientSecret && clientSecret !== DEMO_CLIENT_SECRET) return json({ error: 'invalid_client' }, 401)

  // Single use: taken before any other check can fail.
  const record = await codesApi.take(code)
  if (!record) return json({ error: 'invalid_grant', error_description: 'unknown or already used code' }, 400)
  if (record.expiresAt < Date.now()) return json({ error: 'invalid_grant', error_description: 'code expired' }, 400)
  if (redirectUri && redirectUri !== record.redirectUri) return json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400)

  // PKCE S256 is mandatory, which is what the real providers require too.
  if (!record.codeChallenge) return json({ error: 'invalid_request', error_description: 'pkce is required' }, 400)
  if (!verifier) return json({ error: 'invalid_request', error_description: 'code_verifier missing' }, 400)
  const challenge = await sha256Base64Url(verifier)
  if (challenge !== record.codeChallenge) return json({ error: 'invalid_grant', error_description: 'code_verifier does not match' }, 400)

  const now = Math.floor(Date.now() / 1000)
  const origin = new URL(request.url).origin
  const claims = {
    iss: origin,
    aud: record.clientId || DEMO_CLIENT_ID,
    sub: DEMO_SUBJECT,
    exp: now + 600,
    iat: now,
    nonce: record.nonce,
    email: DEMO_EMAIL,
    email_verified: true,
    name: DEMO_NAME,
    preferred_username: 'demo',
    picture: origin + '/avatar.png',
  }
  const idToken = await signIdToken(claims)
  return json({
    access_token: randomToken(32),
    token_type: 'Bearer',
    expires_in: 600,
    id_token: idToken,
    scope: record.scope,
  })
}

export function userinfo(issuer) {
  return json({
    sub: DEMO_SUBJECT,
    email: DEMO_EMAIL,
    email_verified: true,
    name: DEMO_NAME,
    preferred_username: 'demo',
    picture: issuer + '/avatar.png',
  })
}
