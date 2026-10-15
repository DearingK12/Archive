# ASKODA deployment security

Before setting `NODE_ENV=production`:

1. Revoke the OpenAI key that was previously exposed and create a replacement.
2. Create a Google OAuth web client and add the exact HTTPS deployment origin to its allowed JavaScript origins.
3. Generate a unique secret with `openssl rand -hex 32` and set it as `SESSION_SECRET`.
4. Set `TRUST_PROXY=true` only when the app is directly behind one trusted HTTPS reverse proxy.
5. Configure the hosting platform to terminate HTTPS and redirect HTTP to HTTPS. The app also returns a `308` redirect in production.
6. Store secrets in the host's secret manager, never in source control or client-side code.
7. Replace `data/state.json` with PostgreSQL before running multiple instances or storing important user data.
8. Back up the database and test restore before launch.

The server rejects placeholder production credentials at startup. Run `npm audit --omit=dev` before each deployment.