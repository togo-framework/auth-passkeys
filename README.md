<div align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/togo-mark-dark.svg" /><img src=".github/assets/togo-mark.svg" alt="ToGO" height="64" /></picture>
  <h1>togo-framework/auth-passkeys</h1>
  <p>
    <a href="https://to-go.dev/marketplace"><img src="https://img.shields.io/badge/marketplace-to--go.dev-1F8A99" alt="marketplace" /></a>
    <a href="https://pkg.go.dev/github.com/togo-framework/auth-passkeys"><img src="https://pkg.go.dev/badge/github.com/togo-framework/auth-passkeys.svg" alt="pkg.go.dev" /></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT" />
  </p>
  <p><strong>WebAuthn / passkey (FIDO2) passwordless login for the <a href="https://to-go.dev">togo</a> auth family.</strong></p>
</div>

## Install

```bash
togo install togo-framework/auth-passkeys
```

Adds **passkey** registration + login ceremonies to a togo app. On a successful passkey login it issues a session via the [`auth`](https://to-go.dev/plugins/auth) plugin — so passkeys slot into your existing auth flow as a passwordless method.

## Configuration

| Env | Description |
|---|---|
| `PASSKEYS_RP_ID` | Relying-party ID — your domain (e.g. `localhost`, `fort.example.com`) |
| `PASSKEYS_RP_NAME` | Display name shown in the authenticator prompt |
| `PASSKEYS_RP_ORIGINS` | Comma-separated allowed origins (e.g. `https://app.example.com`) |

## Endpoints

| Method | Path | Ceremony |
|---|---|---|
| `POST` | `/api/auth/passkeys/register/begin` | → `PublicKeyCredentialCreationOptions` |
| `POST` | `/api/auth/passkeys/register/finish` | verify attestation + store the credential |
| `POST` | `/api/auth/passkeys/login/begin` | → `PublicKeyCredentialRequestOptions` |
| `POST` | `/api/auth/passkeys/login/finish` | verify assertion → **issue an auth session** |
| `GET` | `/api/auth/passkeys/credentials` | list a user's passkeys |

The ceremony subject is the `user_id` (request body, `?user_id`, or the `X-User-Id` / authenticated user).

## Browser usage

```js
// register
const opts = await (await fetch('/api/auth/passkeys/register/begin', {
  method: 'POST', headers: {'Content-Type':'application/json','X-User-Id': email},
  body: JSON.stringify({ user_id: email })
})).json();
const cred = await navigator.credentials.create({ publicKey: decode(opts.publicKey) });
await fetch('/api/auth/passkeys/register/finish', { method:'POST', headers:{'X-User-Id':email}, body: encode(cred) });

// login
const req = await (await fetch('/api/auth/passkeys/login/begin', {
  method:'POST', body: JSON.stringify({ user_id: email }) })).json();
const assertion = await navigator.credentials.get({ publicKey: decode(req.publicKey) });
const res = await fetch('/api/auth/passkeys/login/finish', { method:'POST', headers:{'X-User-Id':email}, body: encode(assertion) });
// res → { authenticated: true, token } and an auth session cookie
```

## Go API

```go
pk, _ := passkeys.FromKernel(k)
creds := pk.CredentialsFor("alice@example.com")   // a user's passkeys
pk.WithStore(myDBStore)                            // persist credentials (Store interface)
```

Credentials live in a bounded in-memory store by default; implement the `Store` interface (`Add`/`ByUser`/`Get`/`UpdateSignCount`/`Delete`) + `WithStore(...)` for DB persistence.

---

<div align="center">
  <h3>Premium sponsors</h3>
  <p>
    <a href="https://id8media.com"><strong>ID8 Media</strong></a> &nbsp;·&nbsp;
    <a href="https://one-studio.co"><strong>One Studio</strong></a>
  </p>
  <p><sub>Support togo — <a href="https://github.com/sponsors/fadymondy">become a sponsor</a>.</sub></p>
</div>
