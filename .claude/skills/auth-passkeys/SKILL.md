---
name: auth-passkeys
description: Add WebAuthn/passkey (FIDO2) passwordless login to a togo app with the auth-passkeys plugin — registration & login ceremonies that issue an auth session, plus credential storage.
---

# togo auth-passkeys

Use this skill to add passkeys to a togo app.

## Configure
Env: `PASSKEYS_RP_ID` (your domain), `PASSKEYS_RP_NAME`, `PASSKEYS_RP_ORIGINS` (comma list).

## Ceremonies (POST)
- Register: `/api/auth/passkeys/register/begin` → `navigator.credentials.create()` → `/register/finish`.
- Login: `/api/auth/passkeys/login/begin` → `navigator.credentials.get()` → `/login/finish` (issues an auth session via the `auth` plugin).
Subject = `user_id` (body / `?user_id` / `X-User-Id`).

## Notes
- RP_ID must match the site domain and RP_ORIGINS must include the exact origin, or the browser rejects the ceremony.
- Persist credentials for production: implement the `Store` interface + `FromKernel(k).WithStore(db)`; always update `SignCount` on login.
- Pair with the `auth` plugin (it issues the session) and offer passkeys alongside password/OTP.
