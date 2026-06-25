# auth-passkeys — usage

## Configure (env)
- `PASSKEYS_RP_ID` — relying-party id (your domain; `localhost` in dev)
- `PASSKEYS_RP_NAME` — display name in the authenticator prompt
- `PASSKEYS_RP_ORIGINS` — comma-separated allowed origins

## Ceremonies
Registration: `POST /api/auth/passkeys/register/{begin,finish}`.
Login: `POST /api/auth/passkeys/login/{begin,finish}` — on success the `auth`
plugin issues a session (cookie + token).

The subject is the `user_id` (body / `?user_id` / `X-User-Id`).

## Browser
Use `navigator.credentials.create()` with the `/register/begin` options, POST the
result to `/register/finish`; `navigator.credentials.get()` with `/login/begin`,
POST to `/login/finish`. (Base64url-decode the server options' challenge/ids and
encode the credential response — a small helper or `@github/webauthn-json` works.)

## Persistence
Default store is in-memory. Implement the `Store` interface and call
`passkeys.FromKernel(k).WithStore(db)` for a DB-backed credential store; update
the stored `SignCount` on each login (clone/replay detection).
