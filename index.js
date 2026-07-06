const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.set('trust proxy', true);

// ── CORS: only allow requests from the app's own front-end ────────────
// Locks out random websites/scripts running in a browser from calling
// this API. This is one extra layer, not the only one — the API key
// gate below is still the main protection.
const ALLOWED_ORIGIN = 'https://surekhabmspro.github.io';
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());

// ── BASIC RATE LIMITING ─────────────────────────────────────────────────
// Blunts brute-force / scraping attempts against this API. No extra
// package needed — just an in-memory counter per IP address that resets
// every minute. Not as strong as a dedicated service, but a real
// deterrent for an app this size, and completely free.
const RATE_LIMIT_MAX = 120;         // max requests allowed per IP per window
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute window
const _rateHits = new Map();
function rateLimiter(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const entry = _rateHits.get(ip);
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW_MS) {
    _rateHits.set(ip, { start: now, count: 1 });
    return next();
  }
  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests, slow down.' });
  }
  next();
}
// Clears old entries periodically so this stays small in memory.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of _rateHits) {
    if (now - entry.start > RATE_LIMIT_WINDOW_MS) _rateHits.delete(ip);
  }
}, RATE_LIMIT_WINDOW_MS).unref();
app.use(rateLimiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── API KEY GATE ─────────────────────────────────────────────────────
// Every data route below requires a matching x-api-key header. Without
// this, anyone who discovers this URL (search-engine crawlers, random
// scans of *.onrender.com, a leaked link) could read or edit every troop,
// patrol, and the PIN hash with a single request — the app's PIN only
// protected the front-end UI, not this API.
//
// Set the API_KEY environment variable in the Render dashboard (Settings
// → Environment) to a long random value. If it's not set, the server
// refuses to start, so a misconfigured deploy fails loudly instead of
// silently running unprotected.
const API_KEY = process.env.API_KEY;
if (!API_KEY) {
  console.error('FATAL: API_KEY environment variable is not set. Refusing to start unprotected.');
  process.exit(1);
}
function requireApiKey(req, res, next) {
  const key = req.header('x-api-key');
  if (key !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── SELF-MIGRATION: ensure newer troop columns exist ────────────────────
// Runs once on boot. Safe to run every deploy — IF NOT EXISTS makes it a no-op
// once the columns are already there.
async function migrateSchema() {
  try {
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS blood_group TEXT');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS deployment_date DATE');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS weapon_number TEXT');
    console.log('Schema check OK: blood_group, deployment_date, weapon_number present on troops table.');
  } catch (e) {
    console.error('Schema migration failed:', e.message);
  }
}

// ── VERSION (bump this string on every backend deploy) ─────────────────
// Left open — reveals nothing about your data.
const API_VERSION = '2026.07.05.1';
app.get('/version', (_, res) => res.json({ version: API_VERSION }));

// ── HEALTH ────────────────────────────────────────────────────────────
// Left open — just a heartbeat, reveals nothing about your data.
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date() }));

// Everything below this line handles real data and requires the API key.
app.use(requireApiKey);

// ── TROOPS (active) ───────────────────────────────────────────────────
app.get('/troops', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM troops WHERE archived = FALSE ORDER BY name'
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── TROOPS (archived) ─────────────────────────────────────────────────
app.get('/archived', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM troops WHERE archived = TRUE ORDER BY name'
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── UPSERT TROOP ──────────────────────────────────────────────────────
app.post('/troops', async (req, res) => {
  try {
    const { id, name, rank, unit, sn, status, notes, phoneLocal, phoneWa, bloodGroup, deploymentDate, weaponNumber } = req.body;
    await pool.query(
      `INSERT INTO troops (id, name, rank, unit, sn, status, notes, phone_local, phone_wa, blood_group, deployment_date, weapon_number)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (id) DO UPDATE
         SET name=$2, rank=$3, unit=$4, sn=$5, status=$6, notes=$7, phone_local=$8, phone_wa=$9, blood_group=$10, deployment_date=$11, weapon_number=$12`,
      [id, name, rank || '', unit || '', sn || '', status || 'available', notes || '', phoneLocal || '', phoneWa || '', bloodGroup || null, deploymentDate || null, weaponNumber || null]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DELETE TROOP ──────────────────────────────────────────────────────
app.delete('/troops/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM troops WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ARCHIVE / UNARCHIVE TROOP ─────────────────────────────────────────
app.patch('/troops/:id/archive', async (req, res) => {
  try {
    await pool.query(
      'UPDATE troops SET archived = $1 WHERE id = $2',
      [req.body.archived, req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PATROLS ───────────────────────────────────────────────────────────
app.get('/patrols', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM patrols ORDER BY date DESC'
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── UPSERT PATROL ─────────────────────────────────────────────────────
app.post('/patrols', async (req, res) => {
  try {
    const { id, ptl_id, date, type, troops, area, duration, route, remarks, commander, commander_auto } = req.body;
    await pool.query(
      `INSERT INTO patrols (id, ptl_id, date, type, troops, area, duration, route, remarks, commander, commander_auto)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE
         SET ptl_id=$2, date=$3, type=$4, troops=$5, area=$6,
             duration=$7, route=$8, remarks=$9, commander=$10, commander_auto=$11`,
      [id, ptl_id || '', date, type || '', troops || [], area || '',
       parseFloat(duration) || null, route || '', remarks || '', commander || null, (commander_auto === null || commander_auto === undefined) ? null : !!commander_auto]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DELETE PATROL ─────────────────────────────────────────────────────
app.delete('/patrols/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM patrols WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── AUDIT LOG ─────────────────────────────────────────────────────────
app.get('/audit', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM audit_log ORDER BY ts DESC LIMIT 500'
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/audit', async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO audit_log (ts, msg) VALUES ($1, $2)',
      [req.body.ts || new Date().toISOString(), req.body.msg]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── APP CONFIG (settings, patrol types, sectors, routes, ranks) ───────
app.get('/config', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT key, value FROM app_config');
    const config = {};
    rows.forEach(r => { config[r.key] = r.value; });
    res.json(config);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/config', async (req, res) => {
  try {
    const { key, value } = req.body;
    await pool.query(
      `INSERT INTO app_config (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = $2`,
      [key, JSON.stringify(value)]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── START ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
migrateSchema().finally(() => {
  app.listen(PORT, () => {
    console.log(`POB Tracker API running on port ${PORT}`);
  });
});
