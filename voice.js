// Голосовые сообщения: аудио хранится в PostgreSQL и доступно только участникам чата.
module.exports = function (app, pool, auth) {
  const ready = pool.query(`CREATE TABLE IF NOT EXISTS chat_voice(
    id BIGSERIAL PRIMARY KEY,
    room_key TEXT NOT NULL,
    owner VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    mime TEXT NOT NULL,
    data BYTEA NOT NULL,
    duration INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(e => console.error('chat_voice table error:', e.message));

  async function roomFor(me, peer) {
    if (peer === '__rulers_world__') return 'group|rulers';
    if (peer === me) return 'saved|' + me;
    if (!/^[a-z0-9_]{3,20}$/.test(peer)) return null;
    const e = await pool.query('SELECT 1 FROM users WHERE username=$1', [peer]);
    return e.rowCount ? [me, peer].sort().join('|') : null;
  }
  function canRead(key, user) {
    if (key === 'group|rulers') return true;
    const parts = key.split('|');
    return parts[0] === 'saved' ? parts[1] === user : parts.length === 2 && (parts[0] === user || parts[1] === user);
  }

  app.post('/api/voice', auth, async (req, res) => {
    await ready;
    const m = /^data:(audio\/(?:webm|ogg|mp4|mpeg|wav|x-m4a|aac)(?:;codecs=[A-Za-z0-9.,_-]+)?);base64,([A-Za-z0-9+/=]+)$/.exec(String(req.body?.audio || ''));
    const duration = Number(req.body?.duration);
    if (!m || m[2].length > 7000000) return res.status(400).json({ error: 'Голосовое должно быть аудио до 5 МБ' });
    if (!Number.isFinite(duration) || duration < 1 || duration > 300) return res.status(400).json({ error: 'Длительность записи должна быть до 5 минут' });
    try {
      const room = await roomFor(req.username, String(req.body.peer || ''));
      if (!room) return res.status(404).json({ error: 'Чат не найден' });
      const v = await pool.query('INSERT INTO chat_voice(room_key,owner,mime,data,duration) VALUES($1,$2,$3,$4,$5) RETURNING id',
        [room, req.username, m[1], Buffer.from(m[2], 'base64'), Math.round(duration)]);
      const r = await pool.query(
        'INSERT INTO messages(room_key,sender,body) VALUES($1,$2,$3) RETURNING id,sender AS f,body AS x,(EXTRACT(EPOCH FROM created_at)*1000)::bigint AS t',
        [room, req.username, '[voice:' + v.rows[0].id + ':' + Math.round(duration) + ']']);
      res.status(201).json({ message: r.rows[0] });
    } catch (e) { console.error('Send voice:', e.message); res.status(500).json({ error: 'Не удалось отправить голосовое сообщение' }); }
  });

  app.get('/api/voice/:id', auth, async (req, res) => {
    await ready;
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).end();
    try {
      const r = await pool.query('SELECT room_key,mime,data FROM chat_voice WHERE id=$1', [id]);
      if (!r.rowCount) return res.status(404).end();
      if (!canRead(r.rows[0].room_key, req.username)) return res.status(403).end();
      res.set({ 'Content-Type': r.rows[0].mime, 'Cache-Control': 'private, max-age=31536000, immutable', 'X-Content-Type-Options': 'nosniff' }).send(r.rows[0].data);
    } catch (e) { console.error('Load voice:', e.message); res.status(500).end(); }
  });
};
