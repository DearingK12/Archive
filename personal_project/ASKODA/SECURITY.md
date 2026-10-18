# ASKODA deployment security

Before setting `NODE_ENV=production`:

1. Revoke the OpenAI key that was previously exposed and create a replacement.
2. Create a Google OAuth web client and add the exact HTTPS deployment origin to its allowed JavaScript origins.
3. Generate a unique secret with `openssl rand -hex 32` and set it as `SESSION_SECRET`.
4. Set `TRUST_PROXY=true` only when the app is directly behind one trusted HTTPS reverse proxy.
5. Configure the hosting platform to terminate HTTPS and redirect HTTP to HTTPS. The app also returns a `308` redirect in production.
6. Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and a verified `SMTP_FROM` sender for account-verification email. Keep SMTP credentials in the host's secret manager.
7. Store all secrets in the host's secret manager, never in source control or client-side code.
8. Replace `data/state.json` and `data/users.json` with PostgreSQL before running multiple instances or storing important user data.
9. Back up the database and test restore before launch.

Email/password accounts require a six-digit code delivered over SMTP before the first sign-in. Codes expire after 10 minutes, allow five attempts, and can be resent once per minute. Passwords are hashed with Node's scrypt and code hashes are keyed with `SESSION_SECRET`. Password recovery is not implemented. Account records are kept in `data/users.json`; use a properly managed database and add an account-recovery flow before offering these accounts publicly. Keep that file private and backed up.

Notebook JavaScript runs in a separate worker with network connections blocked and a five-second execution limit. It is not a Python runtime; imported Python cells are preserved but cannot be run.

The server rejects placeholder production credentials at startup. Run `npm audit --omit=dev` before each deployment.