// Put the demo on demo.otscup.com.
//
// Two tokens are involved, because they have different permissions:
//  - the main token may write DNS;
//  - the workers token may write Worker routes.
//
// A Workers route needs the name to resolve, and Cloudflare does not create that
// record itself, so a proxied placeholder is added. Requests are then answered by
// the route, exactly like sb.otscup.com works.
import fs from 'node:fs'

const dnsToken = fs.readFileSync('E:\\dsh-home\\.cloudflare\\secrets-broker-token.txt', 'utf8').trim()
const workerToken = fs.readFileSync('E:\\dsh-home\\.cloudflare\\workers-d1-token.txt', 'utf8').trim()
const zone = '9a1893fc52f7a09d766dd9d091376d42'
const host = 'demo.otscup.com'
const script = 'secrets-broker-demo'

async function api(token, method, path, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  console.log(method, path.split('?')[0], response.status, payload.success ? 'ok' : JSON.stringify(payload.errors).slice(0, 200))
  return payload
}

// 1. DNS: a proxied placeholder, which is all a Workers route needs.
const existing = await api(dnsToken, 'GET', `/zones/${zone}/dns_records?name=${host}`)
if ((existing.result ?? []).length === 0) {
  await api(dnsToken, 'POST', `/zones/${zone}/dns_records`, { type: 'AAAA', name: host, content: '100::', proxied: true, ttl: 1 })
} else {
  console.log('DNS already present:', existing.result.map((r) => r.type + ' ' + r.content).join(', '))
}

// 2. Route: send the host to the demo script.
const routes = await api(workerToken, 'GET', `/zones/${zone}/workers/routes`)
const pattern = `${host}/*`
const current = (routes.result ?? []).find((route) => route.pattern === pattern)
if (current && current.script === script) console.log('route already points at', script)
else if (current) await api(workerToken, 'PUT', `/zones/${zone}/workers/routes/${current.id}`, { pattern, script })
else await api(workerToken, 'POST', `/zones/${zone}/workers/routes`, { pattern, script })
