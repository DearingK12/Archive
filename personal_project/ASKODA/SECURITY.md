# ASKODA deployment security

Before setting `NODE_ENV=production`:

1. Revoke the OpenAI key that was previously exposed and create a replacement.
2. Create a Google OAuth web client and add the exact HTTPS deployment origin to its allowed JavaScript origins.
3. Generate a unique secret with `openssl rand -hex 32` and set it as `SESSION_SECRET`.
4. Set `TRUST_PROXY=true` only when the app is directly behind one trusted HTTPS reverse proxy.
5. Configure the hosting platform to terminate HTTPS and redirect HTTP to HTTPS. The app also returns a `308` redirect in production.
6. Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and a verified `SMTP_FROM` sender for account-verification email. For Gmail, use `smtp.gmail.com` on port `587` with STARTTLS, and create a Google App Password; do not use your normal Google password. The sender must be the Gmail account or a verified send-as address. Keep SMTP credentials in the host's secret manager.
7. Store all secrets in the host's secret manager, never in source control or client-side code.
8. Set `DATABASE_URL` to a private PostgreSQL connection URL before production. Production startup requires it; the app creates its account and workspace tables automatically. Local development may continue using `data/state.json` and `data/users.json`.
9. Back up the database and test restore before launch.

## Render setup

Create a Render Web Service for this repository with `personal_project/ASKODA` as its root directory, `npm ci` as the build command, and `npm start` as the start command. The service listens on Render's `PORT` and requires Node.js 18 or later.

Create a PostgreSQL database in Render and set `DATABASE_URL` on the web service to its private/internal connection URL. Keep the database and service in the same region. The app creates `askoda_users` and `askoda_workspace_state` at startup; the database user must be allowed to create tables.

Set these environment variables in the Render service settings, not in source control:

- `NODE_ENV=production`
- `SESSION_SECRET` (generate a unique value with `openssl rand -hex 32`)
- `GOOGLE_CLIENT_ID`
- `OPENAI_API_KEY` (the replacement key)
- `DATABASE_URL` (Render's private/internal PostgreSQL URL)
- `TRUST_PROXY=true` for Render's HTTPS reverse proxy
- `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_SECURE=false`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` to enable email/password registration

After Render assigns the service its HTTPS URL, add that exact origin (for example, `https://askoda-example.onrender.com`) to the Google OAuth client's authorized JavaScript origins. No path or trailing slash is needed. Do not set `NODE_ENV=production` until the required production secrets and database URL are configured.

Email/password accounts require a six-digit code delivered over SMTP before the first sign-in. Codes expire after 10 minutes, allow five attempts, and can be resent once per minute. Passwords are hashed with Node's scrypt and code hashes are keyed with `SESSION_SECRET`. Password recovery is not implemented. In local development, account records are kept in `data/users.json`; production accounts and workspaces are stored in PostgreSQL. Add an account-recovery flow before offering email/password accounts publicly.

Notebook JavaScript runs in a separate worker with network connections blocked and a five-second execution limit. It is not a Python runtime; imported Python cells are preserved but cannot be run.

The server rejects placeholder production credentials at startup. Run `npm audit --omit=dev` before each deployment.