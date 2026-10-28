// ФабрMoney: слоты v2 (взвешенные символы, таблица выплат ~94% возврата) и ежедневный бонус.
const crypto = require('crypto');
module.exports = function (app, pool, auth) {
  const SYMS = [
    { id: 'egg', w: 30, m: 5 }, { id: 'clover', w: 24, m: 8 }, { id: 'fire', w: 18, m: 12 },
    { id: 'gem', w: 14, m: 20 }, { id: 'crown', w: 9, m: 40 }, { id: 'star', w: 5, m: 100 }
  ];
  const TOTAL = SYMS.reduce((a, s) => a + s.w, 0), PAIR = 1.1;
  const pick = () => { let r = crypto.randomInt(TOTAL); for (const s of SYMS) { if (r < s.w) return s; r -= s.w; } return SYMS[0]; };

  const COOLDOWN = 20 * 3600e3, KEEP = 48 * 3600e3;
  let dailyP = null;
  const dailyInit = () => dailyP || (dailyP = pool.query(`CREATE TABLE IF NOT EXISTS daily_bonus(
    username VARCHAR(20) PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
    last_claim TIMESTAMPTZ NOT NULL, streak INTEGER NOT NULL DEFAULT 1)`).catch(e => { dailyP = null; throw e; }));
  async function dailyState(q, u) {
    const r = await q.query('SELECT streak,(EXTRACT(EPOCH FROM (NOW()-last_claim))*1000)::bigint AS ago FROM daily_bonus WHERE username=$1', [u]);
    const row = r.rows[0], ago = row ? Number(row.ago) : Infinity;
    const streak = row && ago < KEEP ? row.streak : 0, next = Math.min(streak + 1, 7);
    return { available: ago >= COOLDOWN, nextMs: Math.max(0, COOLDOWN - ago), streak, nextStreak: next, reward: 150 + 100 * (next - 1) };
  }

  app.get('/api/fabrlmoney/info', auth, async (req, res) => {
    try {
      await dailyInit();
      res.json({ symbols: SYMS.map(s => ({ id: s.id, mult: s.m })), pair: PAIR, minBet: 10, maxBet: 10000, daily: await dailyState(pool, req.username) });
    } catch (e) { console.error('casino info:', e.message); res.status(500).json({ error: 'Не удалось загрузить казино' }); }
  });

  app.post('/api/fabrlmoney/spin', auth, async (req, res) => {
    const bet = Number(req.body?.bet);
    if (!Number.isSafeInteger(bet) || bet < 10 || bet > 10000) return res.status(400).json({ error: 'Ставка должна быть от 10 до 10 000 золотых яиц' });
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      await c.query('INSERT INTO profiles(username) VALUES($1) ON CONFLICT(username) DO NOTHING', [req.username]);
      const p = await c.query('SELECT balance FROM profiles WHERE username=$1 FOR UPDATE', [req.username]);
      const balance = Number(p.rows[0].balance);
      if (balance < bet) { await c.query('ROLLBACK'); return res.status(400).json({ error: 'Не хватает золотых яиц для ставки' }); }
      const reels = [pick(), pick(), pick()];
      const same = reels[0].id === reels[1].id && reels[1].id === reels[2].id;
      const pair = !same && (reels[0].id === reels[1].id || reels[1].id === reels[2].id || reels[0].id === reels[2].id);
      const payout = same ? bet * reels[0].m : pair ? Math.floor(bet * PAIR) : 0;
      const next = balance - bet + payout;
      await c.query('UPDATE profiles SET balance=$2,updated_at=NOW() WHERE username=$1', [req.username, next]);
      await c.query('COMMIT');
      res.json({
        symbols: reels.map(s => s.id), balance: next, payout, kind: same ? 'triple' : pair ? 'pair' : 'none',
        message: same ? 'ДЖЕКПОТ ×' + reels[0].m + '! Выигрыш ' + payout : pair ? 'Пара! Выплата ' + payout : 'Не повезло, ставка ' + bet + ' сгорела'
      });
    } catch (e) { await c.query('ROLLBACK').catch(() => {}); console.error('FabrlMoney spin:', e.message); res.status(500).json({ error: 'Не удалось прокрутить слоты' }); }
    finally { c.release(); }
  });

  app.post('/api/fabrlmoney/daily', auth, async (req, res) => {
    const c = await pool.connect();
    try {
      await dailyInit();
      await c.query('BEGIN');
      await c.query('INSERT INTO profiles(username) VALUES($1) ON CONFLICT(username) DO NOTHING', [req.username]);
      await c.query('SELECT 1 FROM profiles WHERE username=$1 FOR UPDATE', [req.username]);
      const st = await dailyState(c, req.username);
      if (!st.available) { await c.query('ROLLBACK'); return res.status(400).json({ error: 'Бонус уже получен', nextMs: st.nextMs }); }
      await c.query('INSERT INTO daily_bonus(username,last_claim,streak) VALUES($1,NOW(),$2) ON CONFLICT(username) DO UPDATE SET last_claim=NOW(), streak=EXCLUDED.streak', [req.username, st.nextStreak]);
      const r = await c.query('UPDATE profiles SET balance=balance+$2,updated_at=NOW() WHERE username=$1 RETURNING balance', [req.username, st.reward]);
      await c.query('COMMIT');
      res.json({ reward: st.reward, streak: st.nextStreak, balance: Number(r.rows[0].balance) });
    } catch (e) { await c.query('ROLLBACK').catch(() => {}); console.error('daily:', e.message); res.status(500).json({ error: 'Не удалось получить бонус' }); }
    finally { c.release(); }
  });
};
