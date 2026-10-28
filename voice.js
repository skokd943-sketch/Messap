// Голосовые сообщения. Аудио хранится в БД, в чате лежит сообщение вида [voice:ID:секунды].
module.exports = function (app, pool, auth) {
  const ready = pool.query(`CREATE TABLE IF NOT EXISTS chat_voice(
    id BIGSERIAL PRIMARY KEY,
    room_key TEXT NOT NULL,
    owner VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    mime TEXT NOT NULL,
    seconds INTEGER NOT NULL,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(e => console.error('chat_voice table error:', e.message));

  async function roomFor(me, peer) {
    if (peer === '__rulers_world__') return 'group|rulers';
    if (peer === me) return 'saved|' + me;
    if (!/^[a-z0-9_]{3,20}$/.test(peer)) return null;
    const e = await pool.query('SELECT 1 FROM users WHERE username=$1', [peer]);
    return e.rowCount ? [me, peer].sort().join('|') : null;
  }

  app.post('/api/voice', auth, async (req, res) => {
    await ready;
    const m = /^data:(audio\/[a-z0-9.+-]+)(?:;codecs=[^;,]+)?;base64,([A-Za-z0-9+/=]+)$/i.exec(String(req.body?.audio || ''));
    const dur = Math.round(Number(req.body?.dur));
    if (!m || m[2].length > 1500000) return res.status(400).json({ error: 'Голосовое слишком длинное (максимум около минуты)' });
    if (!Number.isInteger(dur) || dur < 1 || dur > 180) return res.status(400).json({ error: 'Неверная длительность' });
    try {
      const room = await roomFor(req.username, String(req.body.peer || ''));
      if (!room) return res.status(404).json({ error: 'Чат не найден' });
      const v = await pool.query('INSERT INTO chat_voice(room_key,owner,mime,seconds,data) VALUES($1,$2,$3,$4,$5) RETURNING id',
        [room, req.username, m[1].toLowerCase(), dur, Buffer.from(m[2], 'base64')]);
      const r = await pool.query(
        'INSERT INTO messages(room_key,sender,body) VALUES($1,$2,$3) RETURNING id,sender AS f,body AS x,(EXTRACT(EPOCH FROM created_at)*1000)::bigint AS t',
        [room, req.username, '[voice:' + v.rows[0].id + ':' + dur + ']']);
      if (app.locals.notify) app.locals.notify(room, req.username, 'Голосовое сообщение');
      res.status(201).json({ message: r.rows[0] });
    } catch (e) { console.error(e.message); res.status(500).json({ error: 'Не удалось отправить голосовое' }); }
  });

  app.get('/api/voice/:id', auth, async (req, res) => {
    await ready;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).end();
    try {
      const r = await pool.query('SELECT room_key,mime,data FROM chat_voice WHERE id=$1', [id]);
      if (!r.rowCount) return res.status(404).end();
      const key = r.rows[0].room_key, [a, b] = key.split('|'), u = req.username;
      const ok = key === 'group|rulers' || (a === 'saved' ? b === u : (a === u || b === u));
      if (!ok) return res.status(403).end();
      res.set({ 'Content-Type': r.rows[0].mime, 'Cache-Control': 'private, max-age=31536000, immutable' }).send(r.rows[0].data);
    } catch (e) { console.error(e.message); res.status(500).end(); }
  });
};
