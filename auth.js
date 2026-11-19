import { neon } from '@neondatabase/serverless';
import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  createHmac
} from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const COOKIE = 'r67_session';
const SESSION_SECONDS = 60 * 60 * 24 * 7;

function send(res, status, body) {
  res.status(status).json(body);
}
function cookieOptions(maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}
function sign(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verify(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = createHmac('sha256', secret).update(parts[0]).digest();
  let actual;
  try { actual = Buffer.from(parts[1], 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const match = raw.split(';').map(x => x.trim()).find(x => x.startsWith(name + '='));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}
function setSession(res, user, secret) {
  const now = Math.floor(Date.now() / 1000);
  const token = sign({ sub: String(user.id), username: user.username, iat: now, exp: now + SESSION_SECONDS }, secret);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_SECONDS}${secure}`);
}
async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64);
  return `${salt.toString('hex')}:${Buffer.from(derived).toString('hex')}`;
}
async function checkPassword(password, stored) {
  const [saltHex, hashHex] = String(stored).split(':');
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = Buffer.from(await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = String(req.query.action || '');
  if (!['me', 'register', 'login', 'logout'].includes(action)) {
    return send(res, 404, { error: 'Unknown account action.' });
  }
  if (action === 'logout') {
    res.setHeader('Set-Cookie', cookieOptions(0));
    return send(res, 200, { ok: true });
  }

  const databaseUrl = process.env.DATABASE_URL;
  const secret = process.env.SESSION_SECRET;
  if (!databaseUrl || !secret || secret.length < 32) {
    return send(res, 503, { error: 'Account service is not configured yet.' });
  }

  try {
    const sql = neon(databaseUrl);

    if (action === 'me') {
      const session = verify(getCookie(req, COOKIE), secret);
      if (!session) return send(res, 200, { user: null });
      const rows = await sql`SELECT id, username FROM users WHERE id = ${Number(session.sub)} LIMIT 1`;
      if (!rows.length) return send(res, 200, { user: null });
      return send(res, 200, { user: { username: rows[0].username } });
    }

    if (req.method !== 'POST') return send(res, 405, { error: 'Use POST for this action.' });
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
      return send(res, 400, { error: 'Username must be 3–20 characters using letters, numbers, or underscores.' });
    }
    if (password.length < 10 || password.length > 128) {
      return send(res, 400, { error: 'Password must be between 10 and 128 characters.' });
    }

    if (action === 'register') {
      const passwordHash = await hashPassword(password);
      try {
        const rows = await sql`
          INSERT INTO users (username, username_normalized, password_hash)
          VALUES (${username}, ${username.toLowerCase()}, ${passwordHash})
          RETURNING id, username
        `;
        const user = rows[0];
        setSession(res, user, secret);
        return send(res, 201, { user: { username: user.username } });
      } catch (err) {
        if (err.code === '23505') return send(res, 409, { error: 'That username is already taken.' });
        throw err;
      }
    }

    const rows = await sql`
      SELECT id, username, password_hash
      FROM users
      WHERE username_normalized = ${username.toLowerCase()}
      LIMIT 1
    `;
    if (!rows.length || !(await checkPassword(password, rows[0].password_hash))) {
      return send(res, 401, { error: 'Incorrect username or password.' });
    }
    setSession(res, rows[0], secret);
    return send(res, 200, { user: { username: rows[0].username } });
  } catch (err) {
    console.error('Account API error:', err);
    return send(res, 500, { error: 'The account service had a problem. Please try again later.' });
  }
}
