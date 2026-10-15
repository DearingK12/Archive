const express = require('express');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs/promises');
const cookie = require('cookie');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const SESSION_COOKIE = 'askoda_session';
const nodeEnv = (process.env.NODE_ENV || '').toLowerCase();
const isProduction = nodeEnv === 'production';
const sessionSecret = process.env.SESSION_SECRET;
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

function isPlaceholder(value) {
  return !value || /replace-with|your-google|generate-a-random/i.test(value);
}

if (isProduction) {
  if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters in production.');
  }
  if (isPlaceholder(googleClientId)) throw new Error('A real GOOGLE_CLIENT_ID is required in production.');
  if (isPlaceholder(process.env.OPENAI_API_KEY)) throw new Error('A real OPENAI_API_KEY is required in production.');
}

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false }));
app.use((req, res, next) => {
  if (isProduction && req.get('x-forwarded-proto') !== 'https' && !req.secure) {
    return res.redirect(308, `https://${req.get('host')}${req.originalUrl}`);
  }
  next();
});
app.use(express.json({ limit: '32kb' }));
app.use((req, res, next) => {
  req.setTimeout(35_000);
  res.setTimeout(35_000);
  next();
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' }
});
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Chat rate limit reached. Please try again shortly.' }
});
app.use('/api', apiLimiter);

function parseCookies(req) {
  return cookie.parse(req.headers.cookie || '');
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (!origin) return next();

  try {
    if (new URL(origin).origin !== `${req.protocol}://${req.get('host')}`) {
      return res.status(403).json({ error: 'Cross-origin request blocked.' });
    }
  } catch (error) {
    return res.status(403).json({ error: 'Invalid request origin.' });
  }
  next();
}

function requireSession(req, res, next) {
  if (!sessionSecret) return res.status(503).json({ error: 'Authentication is not configured.' });
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return res.status(401).json({ error: 'Authentication required.' });

  try {
    req.user = jwt.verify(token, sessionSecret, { algorithms: ['HS256'], issuer: 'askoda' });
    next();
  } catch (error) {
    res.clearCookie(SESSION_COOKIE);
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

async function readStateStore() {
  try {
    return JSON.parse(await fs.readFile(STATE_FILE, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

async function writeStateStore(store) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const temporaryFile = `${STATE_FILE}.${process.pid}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(store, null, 2), { mode: 0o600 });
  await fs.rename(temporaryFile, STATE_FILE);
}

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.get('/api/config', (req, res) => {
  res.json({ googleClientId: googleClientId || null, isProduction });
});

app.post('/api/auth/google', requireSameOrigin, async (req, res) => {
  if (!googleClient || !googleClientId || !sessionSecret) {
    return res.status(503).json({ error: 'Google authentication is not configured.' });
  }

  const { credential } = req.body || {};
  if (typeof credential !== 'string' || credential.length > 4096) {
    return res.status(400).json({ error: 'A valid Google credential is required.' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: googleClientId });
    const payload = ticket.getPayload();
    if (!payload || !payload.sub || payload.email_verified !== true) {
      return res.status(401).json({ error: 'Google account could not be verified.' });
    }

    const sessionToken = jwt.sign(
      { sub: payload.sub, name: payload.name, email: payload.email, picture: payload.picture },
      sessionSecret,
      { algorithm: 'HS256', expiresIn: '7d', issuer: 'askoda' }
    );
    res.setHeader('Set-Cookie', cookie.serialize(SESSION_COOKIE, sessionToken, {
      httpOnly: true, secure: isProduction, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60, path: '/'
    }));
    res.json({ user: { id: payload.sub, name: payload.name, email: payload.email, picture: payload.picture } });
  } catch (error) {
    console.error('Google authentication error:', error.message);
    res.status(401).json({ error: 'Google authentication failed.' });
  }
});

app.post('/api/auth/demo', requireSameOrigin, (req, res) => {
  if (isProduction) return res.status(404).json({ error: 'Not found.' });
  if (!sessionSecret) return res.status(503).json({ error: 'Authentication is not configured.' });

  const sessionToken = jwt.sign({ sub: 'demo-user', name: 'Demo Creator' }, sessionSecret, {
    algorithm: 'HS256', expiresIn: '1d', issuer: 'askoda'
  });
  res.setHeader('Set-Cookie', cookie.serialize(SESSION_COOKIE, sessionToken, {
    httpOnly: true, secure: false, sameSite: 'lax', maxAge: 24 * 60 * 60, path: '/'
  }));
  res.json({ user: { id: 'demo-user', name: 'Demo Creator', email: 'creator@askoda.ai' } });
});

app.post('/api/auth/signout', requireSameOrigin, (req, res) => {
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' });
  res.status(204).end();
});

app.get('/api/state', requireSession, async (req, res) => {
  try {
    const store = await readStateStore();
    res.json(store[req.user.sub] || null);
  } catch (error) {
    console.error('State read error:', error);
    res.status(500).json({ error: 'Could not load workspace state.' });
  }
});

app.put('/api/state', requireSameOrigin, requireSession, async (req, res) => {
  const { settings, projects, notebooks } = req.body || {};
  if (!settings || !Array.isArray(projects) || !Array.isArray(notebooks)) {
    return res.status(400).json({ error: 'Workspace state has an invalid shape.' });
  }
  if (JSON.stringify({ settings, projects, notebooks }).length > 2_000_000) {
    return res.status(413).json({ error: 'Workspace state is too large.' });
  }

  try {
    const store = await readStateStore();
    const updatedAt = new Date().toISOString();
    store[req.user.sub] = { settings, projects, notebooks, updatedAt };
    await writeStateStore(store);
    res.json({ saved: true, updatedAt });
  } catch (error) {
    console.error('State write error:', error);
    res.status(500).json({ error: 'Could not save workspace state.' });
  }
});

app.post('/api/chat', requireSameOrigin, chatLimiter, requireSession, async (req, res) => {
  const { prompt, systemContext = '' } = req.body || {};
  if (typeof prompt !== 'string' || prompt.trim().length === 0 || prompt.length > 12000) {
    return res.status(400).json({ error: 'Prompt must be between 1 and 12,000 characters.' });
  }
  if (typeof systemContext !== 'string' || systemContext.length > 12000) {
    return res.status(400).json({ error: 'System context is too large.' });
  }
  if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: 'AI service is not configured.' });

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [{ role: 'system', content: systemContext }, { role: 'user', content: prompt }],
        max_tokens: 2000
      }),
      signal: AbortSignal.timeout(30_000)
    });
    const data = await response.json();
    if (!response.ok) return res.status(502).json({ error: 'AI provider request failed.' });
    if (!data.choices?.[0]?.message?.content) return res.status(502).json({ error: 'AI provider returned no response.' });
    res.json({ reply: data.choices[0].message.content });
  } catch (error) {
    console.error('AI provider error:', error.message);
    res.status(502).json({ error: 'Failed to communicate with the AI provider.' });
  }
});

app.use(express.static(path.join(__dirname, 'Public'), { dotfiles: 'deny', maxAge: isProduction ? '1d' : 0 }));
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((error, req, res, next) => {
  console.error('Unhandled server error:', error);
  res.status(500).json({ error: 'Internal server error.' });
});

const server = app.listen(PORT, () => console.log(`ASKODA Server running at http://localhost:${PORT}`));
function shutdown(signal) {
  console.log(`${signal} received, shutting down.`);
  server.close(() => process.exit(0));
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
