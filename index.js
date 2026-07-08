const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by'); // don't advertise "this server runs Express" to scanners

// ── CORS: only allow requests from the app's own front-end ────────────
// Locks out random websites/scripts running in a browser from calling
// this API. This is one extra layer, not the only one — the API key
// gate below is still the main protection.
const ALLOWED_ORIGIN = 'https://surekhabmspro.github.io';
app.use(cors({
  origin: ALLOWED_ORIGIN,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-api-key']
}));
app.use(express.json({ limit: '200kb' })); // caps request size against oversized-payload abuse

// ── REQUEST LOG ───────────────────────────────────────────────────────
// A simple visible trail in Render's Logs tab of who hit what and when —
// useful if you ever need to check whether something unusual happened.
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.path, 'from', req.ip);
  next();
});

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

// ── SECURITY HEADERS ─────────────────────────────────────────────────
// Standard hardening headers, set by hand so no extra package (like
// "helmet") needs to be installed. These tell browsers: don't guess file
// types, don't let this API be framed by another site, and don't leak
// this URL as a referrer to other sites.
app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,                       // cap simultaneous DB connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});
// If a query somehow hangs (bad data, huge query, etc.), cut it off after
// 10 seconds instead of letting it tie up a connection forever.
pool.on('connect', (client) => { client.query('SET statement_timeout = 10000'); });

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
// Timing-safe comparison: a plain !== check leaks tiny timing differences
// that could theoretically help an attacker guess the key character by
// character. This compares in constant time instead.
function safeCompare(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
function requireApiKey(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const blockEntry = _badKeyBlocks.get(ip);
  if (blockEntry && now < blockEntry.until) {
    return res.status(403).json({ error: 'Too many invalid attempts. Blocked temporarily.' });
  }
  const key = req.header('x-api-key') || '';
  if (!safeCompare(key, API_KEY)) {
    console.warn('Rejected request with invalid API key from IP:', ip);
    const rec = _badKeyFails.get(ip) || { count: 0, start: now };
    if (now - rec.start > BAD_KEY_WINDOW_MS) { rec.count = 0; rec.start = now; }
    rec.count++;
    _badKeyFails.set(ip, rec);
    if (rec.count >= BAD_KEY_MAX) {
      _badKeyBlocks.set(ip, { until: now + BAD_KEY_BLOCK_MS });
      _badKeyFails.delete(ip);
      console.warn('IP temporarily blocked for repeated invalid API key attempts:', ip);
    }
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── INPUT VALIDATION ──────────────────────────────────────────────────
// Even with a valid key, this stops obviously malformed or oversized
// data from being written — caps free-text field lengths and makes sure
// an "id" is actually a real, short string before it ever reaches the
// database.
function clip(v, max) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}
function isValidId(v) {
  return typeof v === 'string' && v.trim().length > 0 && v.length <= 100;
}

// ── INVALID-KEY IP BLOCK ───────────────────────────────────────────────
// Separate from the general rate limiter: specifically watches for an IP
// repeatedly sending a wrong API key (a probing/brute-force pattern) and
// blocks that IP outright for a while, on top of everything else.
const BAD_KEY_MAX = 10;             // wrong-key attempts allowed
const BAD_KEY_WINDOW_MS = 10 * 60 * 1000;  // ...within this window
const BAD_KEY_BLOCK_MS = 15 * 60 * 1000;   // ...before a 15-minute block
const _badKeyFails = new Map();
const _badKeyBlocks = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of _badKeyFails) { if (now - rec.start > BAD_KEY_WINDOW_MS) _badKeyFails.delete(ip); }
  for (const [ip, rec] of _badKeyBlocks) { if (now > rec.until) _badKeyBlocks.delete(ip); }
}, 60000).unref();

// ── SELF-MIGRATION: ensure newer troop columns exist ────────────────────
// Runs once on boot. Safe to run every deploy — IF NOT EXISTS makes it a no-op
// once the columns are already there.
async function migrateSchema() {
  try {
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS blood_group TEXT');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS deployment_date DATE');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS weapon_number TEXT');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS gender TEXT');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS category TEXT');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS trade TEXT');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS driver_quals TEXT');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS target_pct INTEGER DEFAULT 100');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS never_suggest BOOLEAN DEFAULT FALSE');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS restricted_range BOOLEAN DEFAULT FALSE');
    console.log('Schema check OK: blood_group, deployment_date, weapon_number, gender, category, trade, driver_quals, target_pct, never_suggest, restricted_range present on troops table.');
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
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── TROOPS (archived) ─────────────────────────────────────────────────
app.get('/archived', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM troops WHERE archived = TRUE ORDER BY name'
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── UPSERT TROOP ──────────────────────────────────────────────────────
app.post('/troops', async (req, res) => {
  try {
    const { id, name, rank, unit, sn, status, notes, phoneLocal, phoneWa, bloodGroup, deploymentDate, weaponNumber, gender, category, trade, driverQuals, targetPct, neverSuggest, restrictedRange } = req.body;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid troop id.' });
    await pool.query(
      `INSERT INTO troops (id, name, rank, unit, sn, status, notes, phone_local, phone_wa, blood_group, deployment_date, weapon_number, gender, category, trade, driver_quals, target_pct, never_suggest, restricted_range)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
       ON CONFLICT (id) DO UPDATE
         SET name=$2, rank=$3, unit=$4, sn=$5, status=$6, notes=$7, phone_local=$8, phone_wa=$9, blood_group=$10, deployment_date=$11, weapon_number=$12,
             gender=$13, category=$14, trade=$15, driver_quals=$16, target_pct=$17, never_suggest=$18, restricted_range=$19`,
      [id, clip(name,200), clip(rank||'',100), clip(unit||'',100), clip(sn||'',50), clip(status||'available',30),
       clip(notes||'',5000), clip(phoneLocal||'',30), clip(phoneWa||'',30), bloodGroup?clip(bloodGroup,10):null,
       deploymentDate || null, weaponNumber?clip(weaponNumber,100):null,
       gender?clip(gender,10):null, category?clip(category,20):null, trade?clip(trade,20):null,
       driverQuals?clip(driverQuals,50):null, (Number.isFinite(parseInt(targetPct))?Math.max(0,Math.min(100,parseInt(targetPct))):100),
       !!neverSuggest, !!restrictedRange]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── DELETE TROOP ──────────────────────────────────────────────────────
app.delete('/troops/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM troops WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── ARCHIVE / UNARCHIVE TROOP ─────────────────────────────────────────
app.patch('/troops/:id/archive', async (req, res) => {
  try {
    await pool.query(
      'UPDATE troops SET archived = $1 WHERE id = $2',
      [req.body.archived, req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── PATROLS ───────────────────────────────────────────────────────────
app.get('/patrols', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM patrols ORDER BY date DESC'
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── UPSERT PATROL ─────────────────────────────────────────────────────
app.post('/patrols', async (req, res) => {
  try {
    const { id, ptl_id, date, type, troops, area, duration, route, remarks, commander, commander_auto } = req.body;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid patrol id.' });
    if (!Array.isArray(troops) || !troops.every(t => typeof t === 'string' && t.length <= 100)) {
      return res.status(400).json({ error: 'Invalid troops list.' });
    }
    await pool.query(
      `INSERT INTO patrols (id, ptl_id, date, type, troops, area, duration, route, remarks, commander, commander_auto)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE
         SET ptl_id=$2, date=$3, type=$4, troops=$5, area=$6,
             duration=$7, route=$8, remarks=$9, commander=$10, commander_auto=$11`,
      [id, clip(ptl_id||'',50), date, clip(type||'',50), troops || [], clip(area||'',200),
       parseFloat(duration) || null, clip(route||'',500), clip(remarks||'',5000), commander || null, (commander_auto === null || commander_auto === undefined) ? null : !!commander_auto]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── DELETE PATROL ─────────────────────────────────────────────────────
app.delete('/patrols/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM patrols WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── AUDIT LOG ─────────────────────────────────────────────────────────
app.get('/audit', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM audit_log ORDER BY ts DESC LIMIT 500'
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

app.post('/audit', async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO audit_log (ts, msg) VALUES ($1, $2)',
      [req.body.ts || new Date().toISOString(), clip(req.body.msg || '', 500)]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── APP CONFIG (settings, patrol types, sectors, routes, ranks) ───────
app.get('/config', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT key, value FROM app_config');
    const config = {};
    rows.forEach(r => {
      let v = r.value;
      if (typeof v === 'string') {
        try { v = JSON.parse(v); } catch (e) { /* leave as-is if it wasn't actually JSON */ }
      }
      config[r.key] = v;
    });
    res.json(config);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
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
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ── CATCH-ALL ─────────────────────────────────────────────────────────
// Any URL that isn't one of the routes above gets a plain, uninformative
// 404 — doesn't hint at what routes do or don't exist.
app.use((req, res) => { res.status(404).json({ error: 'Not found' }); });

// ── START ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
migrateSchema().finally(() => {
  app.listen(PORT, () => {
    console.log(`POB Tracker API running on port ${PORT}`);
  });
});
