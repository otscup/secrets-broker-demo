// The demo vault: a fixed, virtual dataset encrypted with a fixed demo key.
//
// Nothing here talks to a real vault. The rows are generated once, on first use,
// with the same Bitwarden-compatible EncString format the real broker reads, so
// the whole read path (PBKDF2/HKDF in the browser, AES-CBC + HMAC at rest) is
// the real one. Only the storage is fake.
//
// The demo password is public on purpose. Anyone can unlock this vault; that is
// what a demo is. There is no real secret in it.
import { encryptStr, bytesToB64, pbkdf2, hkdfExpand } from './crypto.js'

// Public demo credentials. Shown on the login page.
export const DEMO_EMAIL = 'demo@secrets-broker.local'
export const DEMO_MASTER_PASSWORD = 'demo-master-password'
export const DEMO_KDF_ITERATIONS = 100000

// A fixed 64-byte user key. Deterministic so the seeded rows never change.
function fixedBytes(seed, length) {
  const out = new Uint8Array(length)
  let x = seed >>> 0
  for (let i = 0; i < length; i += 1) {
    x ^= x << 13; x >>>= 0
    x ^= x >>> 17
    x ^= x << 5; x >>>= 0
    out[i] = x & 0xff
  }
  return out
}

export const DEMO_USER_KEY = new Uint8Array([...fixedBytes(0x9e3779b9, 32), ...fixedBytes(0x85ebca6b, 32)])
export const demoEncKey = () => DEMO_USER_KEY.slice(0, 32)
export const demoMacKey = () => DEMO_USER_KEY.slice(32, 64)

// The virtual credentials. Values are obviously fake, so a reader never mistakes
// one for a live key.
const SEED = [
  {
    name: 'openai-prod', group: 'api/prod', url: 'https://api.openai.com',
    username: 'svc-openai', value: 'sk-demo-00000000000000000000000000000001',
    notes: '演示数据：生产环境 OpenAI key',
    kind: 'api', readAllowed: true,
  },
  {
    name: 'stripe-live', group: 'api/prod', url: 'https://api.stripe.com',
    username: 'acct_demo', value: 'sk_live_demo_0000000000000002',
    notes: '演示数据：Stripe 生产密钥',
    kind: 'api', readAllowed: true,
  },
  {
    name: 'github-actions', group: 'api/ci', url: 'https://api.github.com',
    username: 'ci-bot', value: 'ghp_demo0000000000000000000000000003',
    notes: '演示数据：CI 用的 GitHub token',
    kind: 'api', readAllowed: false,
  },
  {
    name: 'github.com', group: 'web', url: 'https://github.com',
    username: 'demo-user', value: 'demo-web-password-4',
    notes: '演示数据：网站登录，只能填充不能读明文',
    kind: 'web', origins: ['https://github.com'], actions: ['login'],
  },
  {
    name: 'aws-console', group: 'web', url: 'https://console.aws.amazon.com',
    username: 'demo-aws', value: 'demo-web-password-5',
    notes: '演示数据：AWS 控制台登录',
    kind: 'web', origins: ['https://console.aws.amazon.com'], actions: ['login'],
  },
  {
    name: 'postgres-analytics', group: 'db', url: '',
    username: 'analytics', value: 'postgres://demo:demo-password-6@db.internal:5432/analytics',
    notes: '演示数据：只读分析库连接串',
    kind: 'api', readAllowed: true,
  },
  {
    name: 'legacy-smtp', group: 'mail', url: '',
    username: 'noreply@demo.local', value: 'demo-smtp-password-7',
    notes: '演示数据：故意留成未分类，用来展示读取被拒',
    kind: null,
  },
]

const DEMO_AGENTS = [
  { name: 'muse', alias: 'Muse', note: '演示 Agent：负责检索', allowAll: true, write: false },
  { name: 'codex', alias: 'Codex', note: '演示 Agent：可以写入演示条目', allowAll: false, allow: ['openai-prod', 'github-actions'], write: true },
  { name: 'reporter', alias: '日报机器人', note: '演示 Agent：只读一个库', allowAll: false, allow: ['postgres-analytics'], write: false },
]

// AES-CBC + HMAC over raw bytes, producing the same EncString shape encryptStr
// does. Needed because the user key is binary, not text.
async function encryptBytes(bytes, encKey, macKey) {
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, ['encrypt'])
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, bytes))
  const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const macInput = new Uint8Array(iv.length + cipher.length)
  macInput.set(iv); macInput.set(cipher, iv.length)
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, macInput))
  return '2.' + bytesToB64(iv) + '|' + bytesToB64(cipher) + '|' + bytesToB64(mac)
}

// The wrapped 64-byte user key. Derived once, then reused.
let cachedProfileKey = null
async function demoProfileKey() {
  if (cachedProfileKey) return cachedProfileKey
  const masterKey = await pbkdf2(DEMO_MASTER_PASSWORD, DEMO_EMAIL.toLowerCase(), DEMO_KDF_ITERATIONS)
  const encKey = await hkdfExpand(masterKey, 'enc', 32)
  const macKey = await hkdfExpand(masterKey, 'mac', 32)
  cachedProfileKey = await encryptBytes(DEMO_USER_KEY, encKey, macKey)
  return cachedProfileKey
}

// Build the virtual D1 rows. Called once per isolate; the result is cached.
let cached = null
export async function demoVault() {
  if (cached) return cached
  const enc = demoEncKey()
  const mac = demoMacKey()
  const now = Date.now()
  // Wrap the demo user key under the demo master password, with the same
  // PBKDF2 -> HKDF -> AES-CBC/HMAC chain a real vault uses. The browser then
  // really derives and unwraps it; only the storage is virtual.
  const profileKey = await demoProfileKey()
  const users = [{
    id: 'demo-user-1', email: DEMO_EMAIL,
    key: profileKey,
    kdf_type: 0, kdf_iterations: DEMO_KDF_ITERATIONS,
    created_at: new Date(now - 90 * 86400e3).toISOString(),
  }]
  const folders = [
    { id: 'folder-1', name: await encryptStr('api', enc, mac), created: now },
    { id: 'folder-2', name: await encryptStr('web', enc, mac), created: now },
  ]
  const ciphers = []
  for (let i = 0; i < SEED.length; i += 1) {
    const item = SEED[i]
    const data = {
      login: {
        username: item.username ? await encryptStr(item.username, enc, mac) : '',
        password: await encryptStr(item.value, enc, mac),
        totp: '',
        uris: item.url ? [{ uri: await encryptStr(item.url, enc, mac) }] : [],
      },
      fields: [],
    }
    ciphers.push({
      id: 'demo-item-' + (i + 1),
      user_id: 'demo-user-1',
      type: 1,
      folder_id: null,
      name: await encryptStr(item.name, enc, mac),
      notes: item.notes ? await encryptStr(item.notes, enc, mac) : '',
      data: JSON.stringify(data),
      key: null,
      created_at: new Date(now - (SEED.length - i) * 3600e3).toISOString(),
      updated_at: new Date(now - i * 60e3).toISOString(),
      deleted_at: null,
      archived_at: null,
      // Demo-only sidecar: which state the UI should show for this item.
      demo: { kind: item.kind, readAllowed: item.readAllowed === true, origins: item.origins ?? [], actions: item.actions ?? [] },
    })
  }
  cached = { users, folders, ciphers, agents: DEMO_AGENTS, seed: SEED }
  return cached
}

export async function demoItemIdByName(name) {
  const vault = await demoVault()
  const index = vault.seed.findIndex((entry) => entry.name === name)
  return index < 0 ? '' : 'demo-item-' + (index + 1)
}

export function demoItemCount() {
  return SEED.length
}

export const demoUserKeyB64 = () => bytesToB64(DEMO_USER_KEY)
