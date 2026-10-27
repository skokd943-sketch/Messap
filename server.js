const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!DATABASE_URL) throw new Error('Set DATABASE_URL in Render environment variables');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('Set SESSION_SECRET to a random value of at least 32 characters');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
app.use(cors({ origin: true }));
app.use(express.json({ limit: '64kb' }));

function sign(username) {
  const payload = Buffer.from(JSON.stringify({ username, exp: Date.now() + 30 * 86400000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function getUser(req) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest();
  let actual;
  try { actual = Buffer.from(sig, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now() && typeof data.username === 'string' ? data.username : null;
  } catch { return null; }
}
function auth(req, res, next) {
  const username = getUser(req);
  if (!username) return res.status(401).json({ error: 'Нужно войти в аккаунт' });
  req.username = username;
  next();
}
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username VARCHAR(20) PRIMARY KEY,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (username ~ '^[a-z0-9_]{3,20}$')
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      room_key TEXT NOT NULL,
      sender VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      body VARCHAR(4000) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS messages_room_id_idx ON messages(room_key, id);
  `);
}
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch (e) { console.error('Health DB error:', e.message); res.status(503).json({ ok: false, database: 'unavailable' }); }
});
app.post('/api/register', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Ник: 3–20 символов, латиница, цифры и _' });
  if (password.length < 6 || password.length > 200) return res.status(400).json({ error: 'Пароль должен содержать от 6 символов' });
  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users(username,password_hash) VALUES($1,$2)', [username, hash]);
    res.status(201).json({ token: sign(username), username });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Такой ник уже занят' });
    console.error('Register error:', e.message); res.status(500).json({ error: 'Не удалось создать аккаунт' });
  }
});
app.post('/api/login', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  try {
    const r = await pool.query('SELECT password_hash FROM users WHERE username=$1', [username]);
    if (!r.rowCount || !(await bcrypt.compare(password, r.rows[0].password_hash))) return res.status(401).json({ error: 'Неверный ник или пароль' });
    res.json({ token: sign(username), username });
  } catch (e) { console.error('Login error:', e.message); res.status(500).json({ error: 'Ошибка входа' }); }
});
app.get('/api/me', auth, (req, res) => res.json({ username: req.username }));
app.get('/api/users', auth, async (_req, res) => {
  try { const r = await pool.query('SELECT username, created_at FROM users ORDER BY username'); res.json({ users: r.rows }); }
  catch (e) { console.error(e.message); res.status(500).json({ error: 'Не удалось загрузить пользователей' }); }
});
app.get('/api/messages', auth, async (req, res) => {
  const peer = String(req.query.peer || '');
  let room;
  if (peer === '__rulers_world__') room = 'group|rulers';
  else if (peer === req.username) room = 'saved|' + req.username;
  else {
    if (!/^[a-z0-9_]{3,20}$/.test(peer)) return res.status(400).json({ error: 'Неверный чат' });
    const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [peer]);
    if (!exists.rowCount) return res.status(404).json({ error: 'Пользователь не найден' });
    room = [req.username, peer].sort().join('|');
  }
  try {
    const r = await pool.query('SELECT id, sender AS f, body AS x, (EXTRACT(EPOCH FROM created_at)*1000)::bigint AS t FROM messages WHERE room_key=$1 ORDER BY id ASC LIMIT 500', [room]);
    res.json({ messages: r.rows });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Не удалось загрузить сообщения' }); }
});
app.post('/api/messages', auth, async (req, res) => {
  const peer = String(req.body?.peer || '');
  const body = String(req.body?.body || '').trim();
  if (!body || body.length > 4000) return res.status(400).json({ error: 'Сообщение должно быть от 1 до 4000 символов' });
  let room;
  if (peer === '__rulers_world__') room = 'group|rulers';
  else if (peer === req.username) room = 'saved|' + req.username;
  else {
    if (!/^[a-z0-9_]{3,20}$/.test(peer)) return res.status(400).json({ error: 'Неверный чат' });
    const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [peer]);
    if (!exists.rowCount) return res.status(404).json({ error: 'Пользователь не найден' });
    room = [req.username, peer].sort().join('|');
  }
  try {
    const r = await pool.query('INSERT INTO messages(room_key,sender,body) VALUES($1,$2,$3) RETURNING id,sender AS f,body AS x,(EXTRACT(EPOCH FROM created_at)*1000)::bigint AS t', [room, req.username, body]);
    res.status(201).json({ message: r.rows[0] });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Не удалось отправить сообщение' }); }
});
app.get('/api/group', auth, async (_req, res) => {
  try {
    const r = await pool.query('SELECT username FROM users ORDER BY username');
    res.json({ title: 'Правители мира', members: r.rows.map(x => x.username) });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Не удалось загрузить группу' }); }
});
app.get('/', (_req, res) => res.send('ФабрLink API is running. Open /api/health to check the database connection.'));
initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log('ФабрLink API listening on port ' + PORT));
}).catch(e => { console.error('Database initialization failed:', e); process.exit(1); });
