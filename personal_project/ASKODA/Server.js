const express = require('express');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const { promisify } = require('util');
const cookie = require('cookie');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.ASKODA_DATA_DIR
  ? path.resolve(process.env.ASKODA_DATA_DIR)
  : path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const databaseUrl = process.env.DATABASE_URL;
const databasePool = databaseUrl ? new Pool({ connectionString: databaseUrl }) : null;
const SESSION_COOKIE = 'askoda_session';
const scrypt = promisify(crypto.scrypt);
const nodeEnv = (process.env.NODE_ENV || '').toLowerCase();
const isProduction = nodeEnv === 'production';
const sessionSecret = process.env.SESSION_SECRET;
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;
const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const smtpFrom = process.env.SMTP_FROM;
const smtpConfigured = Boolean(
  smtpHost && Number.isInteger(smtpPort) && smtpPort > 0 && smtpPort <= 65535 &&
  smtpFrom && ((smtpUser && smtpPass) || (!smtpUser && !smtpPass))
);
const mailTransport = smtpConfigured
  ? nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: process.env.SMTP_SECURE === 'true' || smtpPort === 465,
    ...(smtpUser ? { auth: { user: smtpUser, pass: smtpPass } } : {})
  })
  : null;
const VERIFICATION_CODE_TTL_MS = 10 * 60 * 1000;
const VERIFICATION_RESEND_DELAY_MS = 60 * 1000;
const MAX_VERIFICATION_ATTEMPTS = 5;

function isPlaceholder(value) {
  return !value || /replace-with|your-google|generate-a-random/i.test(value);
}

if (isProduction) {
  if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters in production.');
  }
  if (isPlaceholder(googleClientId)) throw new Error('A real GOOGLE_CLIENT_ID is required in production.');
  if (isPlaceholder(process.env.OPENAI_API_KEY)) throw new Error('A real OPENAI_API_KEY is required in production.');
  if (!databasePool) throw new Error('DATABASE_URL is required in production.');
}

if (databasePool) {
  databasePool.on('error', error => console.error('Unexpected PostgreSQL pool error:', error));
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
app.use(express.json({ limit: '2mb' }));
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
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Please try again later.' }
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

let stateStoreWrite = Promise.resolve();
function updateStateStore(update) {
  const operation = stateStoreWrite.then(async () => {
    const store = await readStateStore();
    const result = await update(store);
    await writeStateStore(store);
    return result;
  });
  stateStoreWrite = operation.catch(() => {});
  return operation;
}

async function readUserStore() {
  try {
    return JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

async function writeUserStore(users) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const temporaryFile = `${USERS_FILE}.${process.pid}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(users, null, 2), { mode: 0o600 });
  await fs.rename(temporaryFile, USERS_FILE);
}

let userStoreWrite = Promise.resolve();
async function readUserRecord(email) {
  if (databasePool) {
    const { rows } = await databasePool.query(
      'SELECT record FROM askoda_users WHERE email = $1',
      [email]
    );
    return rows[0]?.record || null;
  }
  const users = await readUserStore();
  return users[email] || null;
}

function updateUserRecord(email, update) {
  if (databasePool) {
    return updateDatabaseUserRecord(email, update);
  }

  const operation = userStoreWrite.then(async () => {
    const users = await readUserStore();
    const { record, result } = await update(users[email] || null);
    if (record) users[email] = record;
    else delete users[email];
    await writeUserStore(users);
    return result;
  });
  userStoreWrite = operation.catch(() => {});
  return operation;
}

async function updateDatabaseUserRecord(email, update) {
  const client = await databasePool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [email]);
    const { rows } = await client.query(
      'SELECT record FROM askoda_users WHERE email = $1 FOR UPDATE',
      [email]
    );
    const { record, result } = await update(rows[0]?.record || null);
    if (record) {
      await client.query(
        `INSERT INTO askoda_users (email, record)
         VALUES ($1, $2::jsonb)
         ON CONFLICT (email) DO UPDATE SET record = EXCLUDED.record`,
        [email, JSON.stringify(record)]
      );
    } else if (rows.length > 0) {
      await client.query('DELETE FROM askoda_users WHERE email = $1', [email]);
    }
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackError) {
      console.error('PostgreSQL user-store rollback failed:', rollbackError);
    }
    throw error;
  } finally {
    client.release();
  }
}

async function initializeDatabase() {
  await databasePool.query(`
    CREATE TABLE IF NOT EXISTS askoda_users (
      email TEXT PRIMARY KEY,
      record JSONB NOT NULL
    )
  `);
  await databasePool.query(`
    CREATE TABLE IF NOT EXISTS askoda_workspace_state (
      user_id TEXT PRIMARY KEY,
      data JSONB NOT NULL
    )
  `);
}

async function readWorkspaceState(userId) {
  if (databasePool) {
    const { rows } = await databasePool.query(
      'SELECT data FROM askoda_workspace_state WHERE user_id = $1',
      [userId]
    );
    return rows[0]?.data || null;
  }
  const store = await readStateStore();
  return store[userId] || null;
}

async function writeWorkspaceState(userId, data) {
  if (databasePool) {
    await databasePool.query(
      `INSERT INTO askoda_workspace_state (user_id, data)
       VALUES ($1, $2::jsonb)
       ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data`,
      [userId, JSON.stringify(data)]
    );
    return;
  }
  await updateStateStore(store => {
    store[userId] = data;
  });
}

function setSessionCookie(res, user, expiresIn = '7d') {
  const sessionToken = jwt.sign(user, sessionSecret, {
    algorithm: 'HS256',
    expiresIn,
    issuer: 'askoda'
  });
  res.setHeader('Set-Cookie', cookie.serialize(SESSION_COOKIE, sessionToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: expiresIn === '1d' ? 24 * 60 * 60 : 7 * 24 * 60 * 60,
    path: '/'
  }));
}

function publicUser(user) {
  return { id: user.sub, name: user.name, email: user.email, picture: user.picture || null };
}

function verificationCodeHash(email, code) {
  return crypto.createHmac('sha256', sessionSecret).update(`${email}:${code}`).digest('hex');
}

function verificationCodeMatches(email, code, expectedHash) {
  if (typeof expectedHash !== 'string' || !/^[a-f0-9]{64}$/i.test(expectedHash)) return false;
  const actualHash = Buffer.from(verificationCodeHash(email, code), 'hex');
  const savedHash = Buffer.from(expectedHash, 'hex');
  return crypto.timingSafeEqual(actualHash, savedHash);
}

async function sendVerificationCode(record) {
  if (!mailTransport || !smtpFrom) throw new Error('SMTP email delivery is not configured.');
  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
  await mailTransport.sendMail({
    from: smtpFrom,
    to: record.email,
    subject: 'Your ASKODA verification code',
    text: `Hello ${record.name},\n\nYour ASKODA verification code is ${code}.\n\nIt expires in 10 minutes. If you did not create this account, you can ignore this email.`,
    disableFileAccess: true,
    disableUrlAccess: true
  });
  record.verificationCodeHash = verificationCodeHash(record.email, code);
  record.verificationExpiresAt = Date.now() + VERIFICATION_CODE_TTL_MS;
  record.verificationSentAt = Date.now();
  record.verificationAttempts = 0;
}

function verificationCooldown(record) {
  const sentAt = Number(record.verificationSentAt) || 0;
  return Math.max(0, VERIFICATION_RESEND_DELAY_MS - (Date.now() - sentAt));
}

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.get('/api/config', (req, res) => {
  res.json({
    googleClientId: googleClientId || null,
    isProduction,
    allowDemo: !isProduction,
    smtpConfigured
  });
});

app.get('/api/auth/session', requireSession, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post('/api/auth/google', requireSameOrigin, authLimiter, async (req, res) => {
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

    const user = { sub: payload.sub, name: payload.name, email: payload.email, picture: payload.picture };
    setSessionCookie(res, user);
    res.json({ user: publicUser(user) });
  } catch (error) {
    console.error('Google authentication error:', error.message);
    res.status(401).json({ error: 'Google authentication failed.' });
  }
});

app.post('/api/auth/register', requireSameOrigin, authLimiter, async (req, res) => {
  if (!sessionSecret) return res.status(503).json({ error: 'Authentication is not configured.' });
  if (!smtpConfigured) return res.status(503).json({ error: 'Email verification is not configured. Set the SMTP environment variables.' });

  const { name, email, password } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 80) {
    return res.status(400).json({ error: 'Name must be between 1 and 80 characters.' });
  }
  if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (typeof password !== 'string' || password.length < 12 || password.length > 1024) {
    return res.status(400).json({ error: 'Password must be between 12 and 1,024 characters.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  try {
    const salt = crypto.randomBytes(16);
    const passwordHash = await scrypt(password, salt, 64);
    const result = await updateUserRecord(normalizedEmail, async currentRecord => {
      let record = currentRecord;
      if (record?.verifiedAt) return { record, result: { kind: 'existing' } };
      if (record && verificationCooldown(record) > 0) {
        return {
          record,
          result: { kind: 'cooldown', retryAfterSeconds: Math.ceil(verificationCooldown(record) / 1000) }
        };
      }
      if (!record) {
        record = {
          id: crypto.randomUUID(),
          name: name.trim(),
          email: normalizedEmail,
          salt: salt.toString('hex'),
          passwordHash: Buffer.from(passwordHash).toString('hex')
        };
      }
      await sendVerificationCode(record);
      return { record, result: { kind: 'verification-sent' } };
    });
    if (result.kind === 'existing') {
      return res.status(409).json({ error: 'An account with that email already exists. Please sign in.' });
    }
    if (result.kind === 'cooldown') {
      res.set('Retry-After', String(result.retryAfterSeconds));
    }
    res.status(202).json({
      verificationRequired: true,
      message: 'Enter the verification code sent to your email.',
      ...(result.retryAfterSeconds ? { retryAfterSeconds: result.retryAfterSeconds } : {})
    });
  } catch (error) {
    console.error('Account registration email error:', error.message);
    res.status(503).json({ error: 'Could not send the verification email. Check SMTP settings and try again.' });
  }
});

app.post('/api/auth/resend-verification', requireSameOrigin, authLimiter, async (req, res) => {
  if (!sessionSecret) return res.status(503).json({ error: 'Authentication is not configured.' });
  if (!smtpConfigured) return res.status(503).json({ error: 'Email verification is not configured. Set the SMTP environment variables.' });
  const { email } = req.body || {};
  if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    await updateUserRecord(normalizedEmail, async record => {
      if (!record || record.verifiedAt || verificationCooldown(record) > 0) {
        return { record, result: { sent: false } };
      }
      await sendVerificationCode(record);
      return { record, result: { sent: true } };
    });
    res.status(202).json({
      message: 'If the account needs verification, a code has been sent or is still within the resend delay.'
    });
  } catch (error) {
    console.error('Verification email resend error:', error.message);
    res.status(503).json({ error: 'Could not send the verification email. Check SMTP settings and try again.' });
  }
});

app.post('/api/auth/verify-email', requireSameOrigin, authLimiter, async (req, res) => {
  if (!sessionSecret) return res.status(503).json({ error: 'Authentication is not configured.' });

  const { email, code } = req.body || {};
  if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Enter your email and six-digit verification code.' });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const result = await updateUserRecord(normalizedEmail, record => {
      if (!record || record.verifiedAt || !record.verificationCodeHash) {
        return { record, result: { error: 'invalid' } };
      }
      if (Date.now() > Number(record.verificationExpiresAt)) {
        delete record.verificationCodeHash;
        delete record.verificationExpiresAt;
        delete record.verificationAttempts;
        return { record, result: { error: 'expired' } };
      }
      if ((Number(record.verificationAttempts) || 0) >= MAX_VERIFICATION_ATTEMPTS) {
        delete record.verificationCodeHash;
        delete record.verificationExpiresAt;
        delete record.verificationAttempts;
        return { record, result: { error: 'locked' } };
      }
      if (!verificationCodeMatches(normalizedEmail, code, record.verificationCodeHash)) {
        record.verificationAttempts = (Number(record.verificationAttempts) || 0) + 1;
        if (record.verificationAttempts >= MAX_VERIFICATION_ATTEMPTS) {
          delete record.verificationCodeHash;
          delete record.verificationExpiresAt;
          delete record.verificationAttempts;
          return { record, result: { error: 'locked' } };
        }
        return { record, result: { error: 'invalid' } };
      }

      record.verifiedAt = new Date().toISOString();
      delete record.verificationCodeHash;
      delete record.verificationExpiresAt;
      delete record.verificationSentAt;
      delete record.verificationAttempts;
      return {
        record,
        result: { user: { sub: `account:${record.id}`, name: record.name, email: record.email } }
      };
    });

    if (result.error === 'expired') return res.status(410).json({ error: 'That code has expired. Request a new one.' });
    if (result.error === 'locked') return res.status(429).json({ error: 'Too many incorrect codes. Request a new code.' });
    if (result.error) return res.status(400).json({ error: 'The verification code is invalid. Check it and try again.' });
    setSessionCookie(res, result.user);
    res.json({ user: publicUser(result.user) });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Could not verify the email address.' });
  }
});

app.post('/api/auth/login', requireSameOrigin, authLimiter, async (req, res) => {
  if (!sessionSecret) return res.status(503).json({ error: 'Authentication is not configured.' });

  const { email, password } = req.body || {};
  if (typeof email !== 'string' || email.length > 254 || typeof password !== 'string' || password.length > 1024) {
    return res.status(400).json({ error: 'Enter your email and password.' });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const record = await readUserRecord(normalizedEmail);
    const salt = record ? Buffer.from(record.salt, 'hex') : Buffer.alloc(16);
    const expectedHash = record ? Buffer.from(record.passwordHash, 'hex') : Buffer.alloc(64);
    const actualHash = Buffer.from(await scrypt(password, salt, 64));
    if (!record || expectedHash.length !== actualHash.length || !crypto.timingSafeEqual(expectedHash, actualHash)) {
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    }
    if (!record.verifiedAt) {
      return res.status(403).json({
        error: 'Verify your email address before signing in.',
        verificationRequired: true
      });
    }

    const user = { sub: `account:${record.id}`, name: record.name, email: record.email };
    setSessionCookie(res, user);
    res.json({ user: publicUser(user) });
  } catch (error) {
    console.error('Account sign-in error:', error);
    res.status(500).json({ error: 'Could not sign in.' });
  }
});

app.post('/api/auth/demo', requireSameOrigin, (req, res) => {
  if (isProduction) return res.status(404).json({ error: 'Not found.' });
  if (!sessionSecret) return res.status(503).json({ error: 'Authentication is not configured.' });

  const user = { sub: 'demo-user', name: 'Demo Creator', email: 'creator@askoda.ai' };
  setSessionCookie(res, user, '1d');
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/signout', requireSameOrigin, (req, res) => {
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' });
  res.status(204).end();
});

app.get('/api/state', requireSession, async (req, res) => {
  try {
    res.json(await readWorkspaceState(req.user.sub));
  } catch (error) {
    console.error('State read error:', error);
    res.status(500).json({ error: 'Could not load workspace state.' });
  }
});

app.put('/api/state', requireSameOrigin, requireSession, async (req, res) => {
  const { settings, projects, notebooks, conversations = [] } = req.body || {};
  if (!settings || !Array.isArray(projects) || !Array.isArray(notebooks) || !Array.isArray(conversations)) {
    return res.status(400).json({ error: 'Workspace state has an invalid shape.' });
  }
  if (JSON.stringify({ settings, projects, notebooks, conversations }).length > 2_000_000) {
    return res.status(413).json({ error: 'Workspace state is too large.' });
  }

  try {
    const updatedAt = new Date().toISOString();
    await writeWorkspaceState(req.user.sub, { settings, projects, notebooks, conversations, updatedAt });
    res.json({ saved: true, updatedAt });
  } catch (error) {
    console.error('State write error:', error);
    res.status(500).json({ error: 'Could not save workspace state.' });
  }
});

app.post('/api/chat', requireSameOrigin, chatLimiter, requireSession, async (req, res) => {
  const { prompt, messages, systemContext = '' } = req.body || {};
  if (typeof systemContext !== 'string' || systemContext.length > 12000) {
    return res.status(400).json({ error: 'System context is too large.' });
  }
  let conversation;
  if (Array.isArray(messages)) {
    if (messages.length === 0 || messages.length > 20 ||
        messages.some(message => !message || !['user', 'assistant'].includes(message.role) ||
          typeof message.content !== 'string' || !message.content.trim() || message.content.length > 12000) ||
        messages.reduce((total, message) => total + message.content.length, 0) > 40000) {
      return res.status(400).json({ error: 'Conversation messages are invalid or too large.' });
    }
    conversation = messages;
  } else if (typeof prompt === 'string' && prompt.trim().length > 0 && prompt.length <= 12000) {
    conversation = [{ role: 'user', content: prompt }];
  } else {
    return res.status(400).json({ error: 'Prompt must be between 1 and 12,000 characters.' });
  }
  if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: 'AI service is not configured.' });

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [{ role: 'system', content: systemContext }, ...conversation.slice(-12)],
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

app.get('/notebook-worker.js', (req, res) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self' 'unsafe-eval'; connect-src 'none'; worker-src 'none'; object-src 'none';"
  );
  res.sendFile(path.join(__dirname, 'Public', 'notebook-worker.js'));
});

app.use(express.static(path.join(__dirname, 'Public'), { dotfiles: 'deny', maxAge: isProduction ? '1d' : 0 }));
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((error, req, res, next) => {
  console.error('Unhandled server error:', error);
  res.status(500).json({ error: 'Internal server error.' });
});

async function startServer() {
  if (databasePool) await initializeDatabase();
  const server = app.listen(PORT, () => console.log(`ASKODA Server running at http://localhost:${PORT}`));
  function shutdown(signal) {
    console.log(`${signal} received, shutting down.`);
    server.close(() => {
      if (databasePool) {
        databasePool.end().then(() => process.exit(0)).catch(error => {
          console.error('PostgreSQL pool shutdown failed:', error);
          process.exit(1);
        });
      } else {
        process.exit(0);
      }
    });
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

startServer().catch(async error => {
  console.error('ASKODA startup failed:', error);
  if (databasePool) {
    try {
      await databasePool.end();
    } catch (shutdownError) {
      console.error('PostgreSQL pool shutdown failed:', shutdownError);
    }
  }
  process.exitCode = 1;
});
