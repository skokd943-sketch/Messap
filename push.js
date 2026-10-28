// Push-уведомления (Web Push). Ключи VAPID создаются сами и хранятся в app_settings.
// Можно задать свои через переменные Render: VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY.
const webpush = require('web-push');

module.exports = function (app, pool, auth) {
  let initP = null;
  function init() {
    if (initP) return initP;
    initP = (async () => {
      await pool.query(`CREATE TABLE IF NOT EXISTS push_subs(
        endpoint TEXT PRIMARY KEY,
        username VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
        sub JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
      await pool.query('CREATE INDEX IF NOT EXISTS push_subs_user_idx ON push_subs(username)');
      let pub = process.env.VAPID_PUBLIC_KEY, pri = process.env.VAPID_PRIVATE_KEY;
      if (!pub || !pri) {
        const read = async () => {
          const r = await pool.query("SELECT key,value FROM app_settings WHERE key IN ('vapid_public','vapid_private')");
          const o = {}; for (const x of r.rows) o[x.key] = x.value; return o;
        };
        let o = await read();
        if (!o.vapid_public || !o.vapid_private) {
          const k = webpush.generateVAPIDKeys();
          await pool.query("INSERT INTO app_settings(key,value) VALUES('vapid_public',$1),('vapid_private',$2) ON CONFLICT(key) DO NOTHING", [k.publicKey, k.privateKey]);
          o = await read();
        }
        pub = o.vapid_public; pri = o.vapid_private;
      }
      webpush.setVapidDetails('mailto:noreply@fabrlink.app', pub, pri);
      return pub;
    })().catch(e => { console.error('push init:', e.message); initP = null; return null; });
    return initP;
  }

  // room: ключ комнаты, sender: кто написал, text: короткий текст уведомления
  async function notify(room, sender, text) {
    try {
      if (!(await init())) return;
      let users, peerFor, title;
      if (room === 'group|rulers') {
        const r = await pool.query('SELECT DISTINCT username FROM push_subs WHERE username<>$1', [sender]);
        users = r.rows.map(x => x.username); peerFor = () => '__rulers_world__'; title = 'Правители мира';
      } else if (room.startsWith('saved|')) {
        return;
      } else {
        const [a, b] = room.split('|'); users = [a === sender ? b : a]; peerFor = () => sender; title = sender;
      }
      if (!users.length) return;
      // Не шлём тем, кто сейчас в приложении (был активен последние 25 секунд)
      const subs = await pool.query(
        `SELECT ps.endpoint, ps.sub, ps.username FROM push_subs ps
         JOIN users u ON u.username = ps.username
         WHERE ps.username = ANY($1) AND (u.last_seen_at IS NULL OR u.last_seen_at < NOW() - INTERVAL '25 seconds')`, [users]);
      const body = room === 'group|rulers' ? sender + ': ' + text : text;
      await Promise.all(subs.rows.map(async s => {
        const payload = JSON.stringify({ title, body, peer: peerFor(s.username), tag: 'chat-' + peerFor(s.username) });
        try { await webpush.sendNotification(s.sub, payload, { TTL: 3600, urgency: 'high' }); }
        catch (e) {
          if ([401, 403, 404, 410].includes(e.statusCode)) await pool.query('DELETE FROM push_subs WHERE endpoint=$1', [s.endpoint]).catch(() => {});
          else console.error('push send:', e.statusCode || e.message, e.body || '');
        }
      }));
    } catch (e) { console.error('notify:', e.message); }
  }
  app.locals.notify = notify;
  setTimeout(init, 8000);

  // Перехватываем успешную отправку текстового сообщения, не трогая сам обработчик.
  app.post('/api/messages', (req, res, next) => {
    res.on('finish', () => {
      if (res.statusCode !== 201 || !req.username) return;
      const peer = String(req.body?.peer || ''), me = req.username;
      const room = peer === '__rulers_world__' ? 'group|rulers' : peer === me ? null : [me, peer].sort().join('|');
      if (room) notify(room, me, String(req.body?.body || '').trim().slice(0, 140));
    });
    next();
  });

  app.get('/api/push/key', auth, async (_req, res) => {
    const key = await init();
    if (!key) return res.status(503).json({ error: 'Уведомления пока недоступны' });
    res.json({ key });
  });
  app.post('/api/push/subscribe', auth, async (req, res) => {
    const s = req.body?.subscription;
    if (!s || typeof s.endpoint !== 'string' || !/^https:\/\//.test(s.endpoint) || s.endpoint.length > 1000 || !s.keys?.p256dh || !s.keys?.auth)
      return res.status(400).json({ error: 'Неверная подписка' });
    try {
      if (!(await init())) throw new Error('push not ready');
      await pool.query(
        'INSERT INTO push_subs(endpoint,username,sub) VALUES($1,$2,$3) ON CONFLICT(endpoint) DO UPDATE SET username=EXCLUDED.username, sub=EXCLUDED.sub',
        [s.endpoint, req.username, JSON.stringify({ endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } })]);
      await pool.query('DELETE FROM push_subs WHERE username=$1 AND endpoint NOT IN (SELECT endpoint FROM push_subs WHERE username=$1 ORDER BY created_at DESC LIMIT 5)', [req.username]);
      res.json({ ok: true });
    } catch (e) { console.error('subscribe:', e.message); res.status(500).json({ error: 'Не удалось включить уведомления' }); }
  });
  app.post('/api/push/unsubscribe', auth, async (req, res) => {
    try { await pool.query('DELETE FROM push_subs WHERE endpoint=$1 AND username=$2', [String(req.body?.endpoint || ''), req.username]); res.json({ ok: true }); }
    catch (e) { res.status(500).json({ error: 'Не удалось отключить уведомления' }); }
  });
};
