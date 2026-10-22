# Secrets Broker — public demo

A self-contained, throwaway demo of [Secrets Broker](../secrets-broker-workers).
Every credential, agent and audit line is **virtual**. Nothing here talks to
NodeWarden, Bitwarden or any real vault.

**[Try the live demo](https://secrets-broker-demo.vincentdam93.workers.dev)**

## What it is for

The real broker is an agent-facing secrets manager: agents ask for a credential,
you approve it, and the agent gets it over MCP. Showing that needs a running
instance with real secrets in it, which nobody should hand to a stranger on the
internet.

So this is the same UI, wired to a fake vault:

- **Real read path.** The browser derives the master key with PBKDF2, expands it
  with HKDF, unwraps a 64-byte user key, and the rows are stored as real
  Bitwarden `EncString` values (AES-CBC + HMAC-SHA256). The only fake part is
  where the bytes live.
- **Real UI.** Same `src/ui.js` as production: dashboard, globe, items,
  classification, grants, settings.
- **One state, thrown away.** A single Durable Object owns the demo state so
  every request sees the same copy: approve a request and every page agrees. It
  still writes nothing to storage, so a restart reseeds the virtual vault. A
  public demo must not accumulate state an attacker could poison, and a demo
  whose numbers disagree with each other just looks broken.

## Try the demo credentials

Open `/login` and use these:

| What | Value |
| --- | --- |
| Admin password | `demo` |
| Vault master password | `demo-master-password` |

The login page is the production one and offers a single OIDC provider, the
demo's own IdP. Clicking it runs a real authorization-code flow with PKCE S256

## What the seeded vault shows

- Seven credentials mixing all three states: `api` with plaintext reads allowed,
  `api` without, `web` (fill-only) and one deliberately **unclassified**.
- Three agents with different reach: one unrestricted, one limited to two
  credentials with write, one read-only on a single database URL.
- Six grants, including one expired so the "click the duration to extend" row is
  visible.
- Twelve recorded reads across ten cities, which is what the globe draws its
  flight paths from. Each agent gets its own colour, and the legend under the
  globe names them, so a trail can be read as an agent rather than a guess.
- Two approvals waiting and two reminders, so the notice bar, the pending table
  and the approve buttons all have something to act on. Approving works: the
  request clears and the authorisation appears.

The unclassified credential is the interesting one. It demonstrates the
classification switch: while the switch is on (the default, and the real default
too), an unclassified credential cannot be read as plaintext. It is labelled
`未分类 · 禁读` in the items list.

## Run it locally

```bash
npm install
npm run dev      # http://127.0.0.1:8787
npm test         # 14 checks: login, session, real unlock chain, decrypted items, seeded history
```

## Deploy your own copy

```bash
npx wrangler deploy
```

One Worker, static assets, no bindings, no database, no secrets to configure.
Free plan is enough.

## The OIDC login is real, against a local provider

`/login` offers one provider. Choosing it runs the full authorization-code flow:
PKCE S256, a signed state cookie, a nonce, an ES256-signed `id_token`, a JWKS
fetch with signature verification, and claim validation (issuer, audience,
expiry, nonce, subject). The verification module is `src/oidc.js`, imported
unchanged from the real broker, so this is the same code path production runs.

The provider is **inside the demo** (`src/idp.js`), not auth-cf:

- A public demo must not ask strangers to sign in with a real GitHub account.
  That would collect real identities into a throwaway site.
- It would also need a real client secret in a public repository.

So the demo's IdP publishes a real discovery document and a real JWKS, shows a
consent page, and signs visitors in as one fixture user. Its signing key is in
the source on purpose. Never copy that. The protocol is worth reading; the key
management is not.

## Security notes

The demo is public, so read these before copying anything from it.

- **The master password and user key are in the source.** That is the point: the
  vault is fake and anyone may open it. Never seed a real credential into it.
- **The session cookie is HttpOnly, Secure and SameSite.** The demo is
  HTTPS-only, so the flag would otherwise allow a downgrade.
- **No passwords are echoed by the API.** They are published on the login page
  where a visitor looks for them; an API response ends up in logs and devtools
  screenshots far more often.
- **There is no rate limit on login.** The password is public, so a limit would
  protect nothing, and adding one would only get in the way of the demo.
- **Writes are not authenticated beyond the session.** Everything is fake and
  nothing persists, so there is nothing to protect.

What the demo does model correctly is the read path: PBKDF2, HKDF, a wrapped
64-byte user key and real AES-CBC + HMAC rows. That part is worth reading.

## What is intentionally not here

- **No MCP endpoint.** The agent-facing surface needs real identities and real
  approvals to mean anything; a demo one would teach the wrong lesson.
- **No reference to a real identity provider.** The demo runs its own (see
  below) rather than sending visitors to GitHub or a corporate IdP.
- **No notifications.** No tokens to send them with.
- **No persistence.** See above.

Those endpoints still answer, so the UI never breaks, but they say plainly that
they are empty in the demo.

## Layout

```
src/index.js   the demo Worker: session, seeded state, and every /api route
src/vault.js   the virtual vault: credentials, agents, encrypted rows
src/crypto.js  Bitwarden-compatible encryption, shared with the real broker
src/ui.js      the admin UI, unchanged from production
public/        globe bundle and earth texture
test-demo.mjs  14 checks, run with npm test
```

## Licence

AGPL-3.0, same as the broker. See [LICENSE](LICENSE).
