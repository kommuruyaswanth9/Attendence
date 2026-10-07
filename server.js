import express from 'express';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const OTP_EMAIL = process.env.OTP_EMAIL;
const RESEND_FROM = process.env.RESEND_FROM || 'Attendance Tracker <onboarding@resend.dev>';
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!RESEND_API_KEY || !SESSION_SECRET || !OTP_EMAIL) {
  console.warn('\nMissing RESEND_API_KEY, SESSION_SECRET or OTP_EMAIL. Create a .env file before using OTP login.\n');
}
if (SESSION_SECRET && SESSION_SECRET.length < 32) {
  console.warn('\nSESSION_SECRET is short. Use a random 64-character value (see README).\n');
}

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
const challenges = new Map();
const sessions = new Map();
const requestCooldown = new Map();

app.disable('x-powered-by');
app.set('trust proxy', 1); // correct client IP + secure cookies behind Render/Railway/Nginx etc.
app.use(express.json({ limit: '20kb' }));

// Serve ONLY the three public front-end files. (Previously the whole project
// folder was public, which exposed server.js, package.json, README, etc.)
const PUBLIC_FILES = { '/': 'index.html', '/index.html': 'index.html', '/script.js': 'script.js', '/style.css': 'style.css' };
app.get(Object.keys(PUBLIC_FILES), (req, res) => {
  res.sendFile(path.join(__dirname, PUBLIC_FILES[req.path]));
});

function cleanText(value, max) {
  return String(value ?? '').trim().replace(/[<>]/g, '').slice(0, max);
}

function newToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function signSession(sessionId) {
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  return `${sessionId}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || !SESSION_SECRET) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const sessionId = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  if (signature.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  return sessionId;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const pair = raw.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return pair ? decodeURIComponent(pair.slice(name.length + 1)) : '';
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `attendance_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400${secure}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'attendance_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
}

function authenticatedUser(req) {
  const token = getCookie(req, 'attendance_session');
  const sessionId = verifySessionToken(token);
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

function cleanup() {
  const now = Date.now();
  for (const [id, c] of challenges) if (c.expiresAt < now) challenges.delete(id);
  for (const [id, s] of sessions) if (s.expiresAt < now) sessions.delete(id);
  for (const [ip, t] of requestCooldown) if (t < now) requestCooldown.delete(ip);
}
setInterval(cleanup, 30_000).unref();

app.post('/api/send-otp', async (req, res) => {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SERVICE_SID || !SESSION_SECRET) {
    return res.status(500).json({ error: 'Mobile OTP is not configured on the server. Add the Twilio Verify variables and SESSION_SECRET in Render.' });
  }

  const ip = req.ip || 'unknown';
  const lastRequest = requestCooldown.get(ip) || 0;
  if (Date.now() - lastRequest < 30_000) {
    return res.status(429).json({ error: 'Please wait 30 seconds before requesting another OTP.' });
  }

  const name = cleanText(req.body?.name, 80);
  const rollNumber = cleanText(req.body?.rollNumber, 40);
  const phone = cleanText(req.body?.phone, 20).replace(/[\s()-]/g, '');
  if (name.length < 2 || rollNumber.length < 1) {
    return res.status(400).json({ error: 'Enter a valid name and roll number.' });
  }
  if (!/^\+[1-9]\d{7,14}$/.test(phone)) {
    return res.status(400).json({ error: 'Enter a valid mobile number with country code, for example +919876543210.' });
  }

  const challengeId = newToken(24);
  challenges.set(challengeId, { name, rollNumber, phone, expiresAt: Date.now() + 60_000, attempts: 0 });
  requestCooldown.set(ip, Date.now());

  try {
    const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64');
    const response = await fetch(
      `https://verify.twilio.com/v2/Services/${encodeURIComponent(TWILIO_VERIFY_SERVICE_SID)}/Verifications`,
      {
        method: 'POST',
        headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ To: phone, Channel: 'sms' })
      }
    );
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.status !== 'pending') {
      challenges.delete(challengeId);
      requestCooldown.delete(ip);
      console.error('Twilio Verify send error:', result);
      return res.status(502).json({ error: result.message || 'Unable to send the OTP SMS. Check your Twilio Verify configuration.' });
    }
    return res.json({
      success: true,
      challengeId,
      expiresIn: 60,
      message: `OTP sent by SMS to ${phone.slice(0, 3)}******${phone.slice(-2)}.`
    });
  } catch (err) {
    challenges.delete(challengeId);
    requestCooldown.delete(ip);
    console.error('Twilio Verify send error:', err);
    return res.status(502).json({ error: 'Unable to send the OTP SMS. Check your Twilio Verify configuration.' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SERVICE_SID || !SESSION_SECRET) {
    return res.status(500).json({ error: 'Mobile OTP is not configured on the server.' });
  }

  const challengeId = cleanText(req.body?.challengeId, 100);
  const otp = cleanText(req.body?.otp, 6);
  const challenge = challenges.get(challengeId);
  if (!challenge) return res.status(400).json({ error: 'OTP request not found. Request a new OTP.' });
  if (challenge.expiresAt < Date.now()) {
    challenges.delete(challengeId);
    return res.status(400).json({ error: 'OTP expired. Request a new OTP.' });
  }
  if (!/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'Enter the 6-digit OTP.' });

  challenge.attempts += 1;
  if (challenge.attempts > 5) {
    challenges.delete(challengeId);
    return res.status(429).json({ error: 'Too many incorrect attempts. Request a new OTP.' });
  }

  try {
    const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64');
    const response = await fetch(
      `https://verify.twilio.com/v2/Services/${encodeURIComponent(TWILIO_VERIFY_SERVICE_SID)}/VerificationCheck`,
      {
        method: 'POST',
        headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ To: challenge.phone, Code: otp })
      }
    );
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      console.error('Twilio Verify check error:', result);
      return res.status(502).json({ error: result.message || 'OTP verification service is unavailable. Please try again.' });
    }
    if (result.status !== 'approved') {
      return res.status(401).json({ error: `Incorrect OTP. ${Math.max(0, 5 - challenge.attempts)} attempts remaining.` });
    }

    challenges.delete(challengeId);
    const sessionId = newToken(32);
    sessions.set(sessionId, {
      name: challenge.name,
      rollNumber: challenge.rollNumber,
      phone: challenge.phone,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    });
    setSessionCookie(res, signSession(sessionId));
    return res.json({ success: true, user: { name: challenge.name, rollNumber: challenge.rollNumber, phone: challenge.phone } });
  } catch (err) {
    console.error('Twilio Verify check error:', err);
    return res.status(502).json({ error: 'OTP verification service is unavailable. Please try again.' });
  }
});
app.get('/api/session', (req, res) => {
  const user = authenticatedUser(req);
  if (!user) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, user: { name: user.name, rollNumber: user.rollNumber } });
});

app.post('/api/logout', (req, res) => {
  const token = getCookie(req, 'attendance_session');
  const sessionId = verifySessionToken(token);
  if (sessionId) sessions.delete(sessionId);
  clearSessionCookie(res);
  res.json({ success: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Bad JSON bodies etc. -> JSON error instead of an HTML stack trace
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status || 500;
  res.status(status).json({ error: status === 400 ? 'Invalid request.' : 'Server error.' });
});

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[c]));
}

const server = app.listen(PORT, () => {
  console.log(`Attendance Tracker running at http://localhost:${PORT}`);
});
server.on('error', err => {
  if (err.code === 'EADDRINUSE') console.error(`\nPort ${PORT} is already in use. Close the other app or change PORT in .env.\n`);
  else console.error(err);
  process.exit(1);
});
