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
  allowedHeaders: ['Content-Type', 'x-api-key', 'x-session-token']
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

// ── DEVICE SESSIONS ─────────────────────────────────────────────────────
// Replaces the single shared API key as the day-to-day auth for every
// data route below. A device logs in ONCE with the shared master key
// (still the API_KEY value — nothing new to configure in Render) plus a
// label for itself, and gets back its own session token to use from then
// on. Because each device has its own row in `sessions`, devices can be
// individually or collectively signed out from the Devices screen — but
// only by the "main" device (the first to ever log in, or whoever it
// hands that status to). Non-main devices can see the list but can't
// revoke anyone. The master key itself never needs to change for any
// of this, unlike before.
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genSessionId() { return 'sess_' + crypto.randomBytes(12).toString('hex'); }

// POST /login — body: { deviceLabel, masterKey }. Not gated by
// requireSession (a device obviously has no session yet the first time),
// but reuses the exact same bad-key throttling as the old API-key gate so
// this can't be brute-forced any more easily than before.
app.post('/login', async (req, res) => {
  try {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const blockEntry = _badKeyBlocks.get(ip);
    if (blockEntry && now < blockEntry.until) {
      return res.status(403).json({ error: 'Too many invalid attempts. Blocked temporarily.' });
    }
    const masterKey = (req.body && req.body.masterKey) || '';
    if (!safeCompare(masterKey, API_KEY)) {
      console.warn('Rejected login with invalid master key from IP:', ip);
      const rec = _badKeyFails.get(ip) || { count: 0, start: now };
      if (now - rec.start > BAD_KEY_WINDOW_MS) { rec.count = 0; rec.start = now; }
      rec.count++;
      _badKeyFails.set(ip, rec);
      if (rec.count >= BAD_KEY_MAX) {
        _badKeyBlocks.set(ip, { until: now + BAD_KEY_BLOCK_MS });
        _badKeyFails.delete(ip);
        console.warn('IP temporarily blocked for repeated invalid login attempts:', ip);
      }
      return res.status(401).json({ error: 'Incorrect master key.' });
    }
    const deviceLabel = clip((req.body && req.body.deviceLabel) || 'Unnamed device', 100);
    const id = genSessionId();
    const token = genToken();
    // The very first device to ever log in becomes the "main" device —
    // from here on, only the main device can deactivate other devices
    // from Manage Devices (see requireSession/isMain and the /sessions
    // routes below). If the main device is later lost or deactivated,
    // the next device to log in does NOT automatically inherit main
    // status; it has to claim the (now-empty) seat via
    // POST /sessions/claim-main.
    const { rows: countRows } = await pool.query('SELECT COUNT(*)::int AS c FROM sessions');
    const isMain = countRows[0].c === 0;
    await pool.query(
      'INSERT INTO sessions (id, token, device_label, is_main) VALUES ($1, $2, $3, $4)',
      [id, token, deviceLabel, isMain]
    );
    res.json({ token, sessionId: id, deviceLabel, isMain });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// POST /emergency-takeover — body: { deviceLabel, masterKey }. For when
// the main device is lost/broken/inaccessible and no other signed-in
// device is available to hand it off normally (see /sessions/:id/make-main)
// or claim it (see /sessions/claim-main, which only works when NO session
// currently holds main). This is the one path that works from a totally
// new device in every case, because it doesn't require an existing
// session at all — just the shared master key, same as /login.
//
// Deliberately NOT gated by requireSession, and reuses the exact same
// bad-key throttling as /login so it can't be brute-forced any more
// easily than signing in normally already could. Because anyone who
// knows the master key can already sign in as any device today, this
// doesn't introduce a new class of risk — it just closes the gap where
// that same person couldn't also become main without DB access.
//
// What it does: creates a normal new session for this device (same as
// /login), then forcibly revokes and demotes whatever session currently
// holds main (if any) and makes this new session main instead. The old
// main device's session is revoked, not just demoted — if it turns out
// not to be lost after all, it can simply log back in with the master
// key like any other deactivated device. The takeover is written to
// audit_log so it's visible from Duty History → Audit afterward.
app.post('/emergency-takeover', async (req, res) => {
  try {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const blockEntry = _badKeyBlocks.get(ip);
    if (blockEntry && now < blockEntry.until) {
      return res.status(403).json({ error: 'Too many invalid attempts. Blocked temporarily.' });
    }
    const masterKey = (req.body && req.body.masterKey) || '';
    if (!safeCompare(masterKey, API_KEY)) {
      console.warn('Rejected emergency takeover with invalid master key from IP:', ip);
      const rec = _badKeyFails.get(ip) || { count: 0, start: now };
      if (now - rec.start > BAD_KEY_WINDOW_MS) { rec.count = 0; rec.start = now; }
      rec.count++;
      _badKeyFails.set(ip, rec);
      if (rec.count >= BAD_KEY_MAX) {
        _badKeyBlocks.set(ip, { until: now + BAD_KEY_BLOCK_MS });
        _badKeyFails.delete(ip);
        console.warn('IP temporarily blocked for repeated invalid emergency-takeover attempts:', ip);
      }
      return res.status(401).json({ error: 'Incorrect master key.' });
    }
    const deviceLabel = clip((req.body && req.body.deviceLabel) || 'Unnamed device', 100);
    const id = genSessionId();
    const token = genToken();
    const { rows: prevMainRows } = await pool.query('SELECT id, device_label FROM sessions WHERE is_main = TRUE');
    await pool.query('INSERT INTO sessions (id, token, device_label, is_main) VALUES ($1, $2, $3, TRUE)', [id, token, deviceLabel]);
    await pool.query('UPDATE sessions SET is_main = FALSE, revoked = TRUE WHERE id != $1 AND is_main = TRUE', [id]);
    const prevLabel = prevMainRows.length ? prevMainRows[0].device_label : '(none)';
    await pool.query(
      'INSERT INTO audit_log (ts, msg) VALUES ($1, $2)',
      [new Date().toISOString(), clip(`Emergency takeover: "${deviceLabel}" became main device, replacing "${prevLabel}", from IP ${ip}.`, 500)]
    );
    res.json({ token, sessionId: id, deviceLabel, isMain: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// Every real data route requires a valid, non-revoked session token
// instead of the old shared static key.
async function requireSession(req, res, next) {
  try {
    const token = req.header('x-session-token') || '';
    if (!token) return res.status(401).json({ error: 'No session token.', code: 'no_session' });
    const { rows } = await pool.query('SELECT id, revoked, is_main FROM sessions WHERE token = $1', [token]);
    if (rows.length === 0 || rows[0].revoked) {
      return res.status(401).json({ error: 'Session signed out. Please log in again.', code: 'invalid_session' });
    }
    req.sessionId = rows[0].id;
    req.isMain = rows[0].is_main;
    pool.query('UPDATE sessions SET last_seen_at = now() WHERE id = $1', [rows[0].id]).catch(() => {});
    next();
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
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
    // Duty-module fields — added so "Eligible for Roaming duty", "Never
    // assign to duty roster", duty qualifications, and the participation
    // status-tracking fields actually persist across refresh/restart
    // instead of being silently dropped (they were never given columns
    // or wired into the /troops upsert before this).
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS duty_quals TEXT[]');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS is_senior_sergeant BOOLEAN DEFAULT FALSE');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS never_duty BOOLEAN DEFAULT FALSE');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS dual_admin BOOLEAN DEFAULT FALSE');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS status_since DATE');
    await pool.query('ALTER TABLE troops ADD COLUMN IF NOT EXISTS excluded_days INTEGER DEFAULT 0');
    // Manually-logged Leave/Sick/Other absence periods (item 6) — stored as
    // a JSON array of {id,type,start,end,days} so old, previously-untracked
    // time off can be recorded retroactively and excluded from the
    // participation-% window, not just tracked going forward via status.
    await pool.query("ALTER TABLE troops ADD COLUMN IF NOT EXISTS absences JSONB DEFAULT '[]'");
    await pool.query('ALTER TABLE patrols ADD COLUMN IF NOT EXISTS ptl_seq INTEGER');
    // Duties used to live as one big JSON array under app_config.key='duties',
    // overwritten wholesale on every save. That meant ANY unrelated save on
    // ANY device (renaming a rank, editing a setting, etc.) resent that
    // device's own possibly-stale in-memory copy of the whole duties array,
    // silently erasing duties logged moments earlier from a different
    // device — this was the actual cause of "logged duty vanishes on
    // sync". Moving duties to their own table with one row per duty (same
    // pattern as troops/patrols, upserted by id via ON CONFLICT) makes each
    // duty an independent write, so two devices saving different duties at
    // the same time can never clobber each other again.
    await pool.query(`CREATE TABLE IF NOT EXISTS duties (
      id TEXT PRIMARY KEY,
      duty_seq INTEGER,
      date DATE,
      logical_date DATE,
      type TEXT,
      post_id TEXT,
      post_name TEXT,
      start_time TEXT,
      duration_hours NUMERIC,
      troops JSONB DEFAULT '[]',
      remarks TEXT,
      admin_override BOOLEAN DEFAULT FALSE,
      replacements JSONB DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      modified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      cancelled BOOLEAN DEFAULT FALSE,
      cancelled_at TIMESTAMPTZ,
      shift_idx INTEGER,
      shift_idx_count INTEGER,
      duty_id TEXT
    )`);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_duties_date ON duties(date)');
    // One-time cutover: if duties were previously stored in app_config
    // (old format) and the new table is still empty, copy them across so
    // nobody's existing duty history is lost when this upgrade deploys.
    const { rows: dutyCountRows } = await pool.query('SELECT COUNT(*)::int AS c FROM duties');
    if (dutyCountRows[0].c === 0) {
      const { rows: oldDutyRows } = await pool.query(`SELECT value FROM app_config WHERE key = 'duties'`);
      if (oldDutyRows.length > 0) {
        let oldDuties = oldDutyRows[0].value;
        if (typeof oldDuties === 'string') { try { oldDuties = JSON.parse(oldDuties); } catch (e) { oldDuties = []; } }
        if (Array.isArray(oldDuties) && oldDuties.length > 0) {
          for (const d of oldDuties) {
            if (!d || !d.id) continue;
            await pool.query(
              `INSERT INTO duties (id,duty_seq,date,logical_date,type,post_id,post_name,start_time,duration_hours,troops,remarks,admin_override,replacements,created_at,modified_at,cancelled,cancelled_at,shift_idx,shift_idx_count,duty_id)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
               ON CONFLICT (id) DO NOTHING`,
              [d.id, d.dutySeq || null, d.date || null, d.logicalDate || d.date || null, d.type || '', d.postId || null, d.postName || '', d.startTime || null,
               d.durationHours || null, JSON.stringify(d.troops || []), d.remarks || '', !!d.adminOverride, JSON.stringify(d.replacements || []), d.createdAt || new Date().toISOString(),
               d.modifiedAt || new Date().toISOString(), !!d.cancelled, d.cancelledAt || null, d.shiftIdx != null ? d.shiftIdx : null, d.shiftIdxCount != null ? d.shiftIdxCount : null, d.dutyId || '']
            );
          }
          console.log('Migrated', oldDuties.length, 'duties from app_config into the new duties table.');
        }
      }
    }
    // Device sessions (multi-device sign-in/sign-out) — each device that
    // logs in with the shared master key gets its own row here and its own
    // token, so any device can be individually or collectively signed out
    // from the Devices screen without affecting the others or requiring a
    // master-key rotation.
    await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      token TEXT NOT NULL UNIQUE,
      device_label TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      is_main BOOLEAN NOT NULL DEFAULT FALSE
    )`);
    // For deployments where the sessions table already existed before
    // the "main device" concept: add the column without touching
    // existing rows (they stay FALSE until claimed — see /sessions/claim-main).
    await pool.query('ALTER TABLE sessions ADD COLUMN IF NOT EXISTS is_main BOOLEAN NOT NULL DEFAULT FALSE');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)');
    console.log('Schema check OK: blood_group, deployment_date, weapon_number, gender, category, trade, driver_quals, target_pct, never_suggest, restricted_range, duty_quals, is_senior_sergeant, never_duty, status_since, excluded_days, absences, ptl_seq, sessions table present.');
  } catch (e) {
    console.error('Schema migration failed:', e.message);
  }
}

// ── VERSION (bump this string on every backend deploy) ─────────────────
// Left open — reveals nothing about your data.
const API_VERSION = '2026.07.26.1-duties-fix';
app.get('/version', (_, res) => res.json({ version: API_VERSION }));

// ── HEALTH ────────────────────────────────────────────────────────────
// Left open — just a heartbeat, reveals nothing about your data.
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date() }));

// Everything below this line handles real data and requires a valid,
// non-revoked device session (see requireSession above) instead of the
// old shared static key.
app.use(requireSession);

// ── DEVICE SESSIONS MANAGEMENT ─────────────────────────────────────────
// Any already-logged-in device can see every device that's ever logged
// in, but only the main device can sign specific ones (or all others)
// out — enforced via req.isMain, set in requireSession. Signing a
// device out just flips its `revoked` flag — its next request gets a
// 401 with code:'invalid_session', and the front-end sends it back to
// the login screen. No master-key rotation needed, and no limit on how
// many devices can register — see /login above.
app.get('/sessions', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, device_label, created_at, last_seen_at, revoked, is_main FROM sessions ORDER BY last_seen_at DESC'
    );
    res.json(rows.map(r => ({
      id: r.id,
      deviceLabel: r.device_label,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      revoked: r.revoked,
      isMain: r.is_main,
      isCurrent: r.id === req.sessionId
    })));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// Only the main device may deactivate other devices — otherwise any
// device that knows the shared master key could sign in and kick every
// other device out. req.isMain is set by requireSession above.
app.post('/sessions/:id/revoke', async (req, res) => {
  try {
    if (!req.isMain) {
      return res.status(403).json({ error: 'Only the main device can deactivate other devices.' });
    }
    if (req.params.id === req.sessionId) {
      return res.status(400).json({ error: 'Sign out from this device instead of deactivating it here.' });
    }
    await pool.query('UPDATE sessions SET revoked = TRUE WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

app.post('/sessions/revoke-others', async (req, res) => {
  try {
    if (!req.isMain) {
      return res.status(403).json({ error: 'Only the main device can deactivate other devices.' });
    }
    await pool.query('UPDATE sessions SET revoked = TRUE WHERE id != $1', [req.sessionId]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// Permanently deletes deactivated device rows (they're already signed
// out and can't sign back in without the master key, so nothing is lost
// by removing them — this just clears clutter from the Manage Devices
// list). Only the main device can do this, and it never touches active
// sessions regardless of what's passed in.
app.delete('/sessions/revoked', async (req, res) => {
  try {
    if (!req.isMain) {
      return res.status(403).json({ error: 'Only the main device can clear deactivated devices.' });
    }
    const { rowCount } = await pool.query('DELETE FROM sessions WHERE revoked = TRUE');
    res.json({ ok: true, deleted: rowCount });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// Lets the current main device hand main status to another
// already-signed-in device — e.g. when deliberately switching your
// primary phone.
app.post('/sessions/:id/make-main', async (req, res) => {
  try {
    if (!req.isMain) {
      return res.status(403).json({ error: 'Only the main device can do that.' });
    }
    const { rows } = await pool.query('SELECT revoked FROM sessions WHERE id = $1', [req.params.id]);
    if (rows.length === 0 || rows[0].revoked) {
      return res.status(404).json({ error: 'Device not found or already deactivated.' });
    }
    await pool.query('UPDATE sessions SET is_main = FALSE WHERE id != $1', [req.params.id]);
    await pool.query('UPDATE sessions SET is_main = TRUE WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// Recovery path for when the main device was lost, wiped, or
// deactivated and no session currently holds main status: any
// signed-in device can claim it, but only while the seat is genuinely
// empty — so this can't be used to steal main status from an active
// main device.
app.post('/sessions/claim-main', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT COUNT(*)::int AS c FROM sessions WHERE is_main = TRUE AND revoked = FALSE'
    );
    if (rows[0].c > 0) {
      return res.status(403).json({ error: 'A main device is already active.' });
    }
    await pool.query('UPDATE sessions SET is_main = TRUE WHERE id = $1', [req.sessionId]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

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
    const { id, name, rank, unit, sn, status, notes, phoneLocal, phoneWa, bloodGroup, deploymentDate, weaponNumber, gender, category, trade, driverQuals, targetPct, neverSuggest, restrictedRange, dutyQuals, isSeniorSergeant, neverDuty, dualAdmin, statusSince, excludedDays, absences } = req.body;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid troop id.' });
    const dutyQualsArr = Array.isArray(dutyQuals) ? dutyQuals.filter(q => typeof q === 'string').map(q => clip(q, 50)).slice(0, 20) : [];
    // Leave/Sick/Other absence records (item 6) — cap count and validate
    // shape so malformed or oversized input can't be written.
    const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
    const absencesArr = Array.isArray(absences) ? absences.filter(a => a && typeof a === 'object' && ISO_DATE.test(a.start) && ISO_DATE.test(a.end)).slice(0, 200).map(a => ({
      id: clip(a.id || '', 60),
      type: ['Leave', 'Sick', 'Other'].includes(a.type) ? a.type : 'Other',
      start: a.start,
      end: a.end,
      days: Number.isFinite(parseInt(a.days)) ? Math.max(1, parseInt(a.days)) : 1
    })) : [];
    await pool.query(
      `INSERT INTO troops (id, name, rank, unit, sn, status, notes, phone_local, phone_wa, blood_group, deployment_date, weapon_number, gender, category, trade, driver_quals, target_pct, never_suggest, restricted_range, duty_quals, is_senior_sergeant, never_duty, dual_admin, status_since, excluded_days, absences)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
       ON CONFLICT (id) DO UPDATE
         SET name=$2, rank=$3, unit=$4, sn=$5, status=$6, notes=$7, phone_local=$8, phone_wa=$9, blood_group=$10, deployment_date=$11, weapon_number=$12,
             gender=$13, category=$14, trade=$15, driver_quals=$16, target_pct=$17, never_suggest=$18, restricted_range=$19,
             duty_quals=$20, is_senior_sergeant=$21, never_duty=$22, dual_admin=$23, status_since=$24, excluded_days=$25, absences=$26`,
      [id, clip(name,200), clip(rank||'',100), clip(unit||'',100), clip(sn||'',50), clip(status||'available',30),
       clip(notes||'',5000), clip(phoneLocal||'',30), clip(phoneWa||'',30), bloodGroup?clip(bloodGroup,10):null,
       deploymentDate || null, weaponNumber?clip(weaponNumber,100):null,
       gender?clip(gender,10):null, category?clip(category,20):null, trade?clip(trade,20):null,
       driverQuals?clip(driverQuals,50):null, (Number.isFinite(parseInt(targetPct))?Math.max(0,Math.min(100,parseInt(targetPct))):100),
       !!neverSuggest, !!restrictedRange,
       dutyQualsArr, !!isSeniorSergeant, !!neverDuty, !!dualAdmin, statusSince || null,
       (Number.isFinite(parseInt(excludedDays))?parseInt(excludedDays):0), JSON.stringify(absencesArr)]
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
    const { id, ptl_id, ptl_seq, date, type, troops, area, duration, route, remarks, commander, commander_auto } = req.body;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid patrol id.' });
    if (!Array.isArray(troops) || !troops.every(t => typeof t === 'string' && t.length <= 100)) {
      return res.status(400).json({ error: 'Invalid troops list.' });
    }
    await pool.query(
      `INSERT INTO patrols (id, ptl_id, ptl_seq, date, type, troops, area, duration, route, remarks, commander, commander_auto)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (id) DO UPDATE
         SET ptl_id=$2, ptl_seq=$3, date=$4, type=$5, troops=$6, area=$7,
             duration=$8, route=$9, remarks=$10, commander=$11, commander_auto=$12`,
      [id, clip(ptl_id||'',50), (Number.isFinite(parseInt(ptl_seq))?parseInt(ptl_seq):null), date, clip(type||'',50), troops || [], clip(area||'',200),
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

// ── DUTIES ────────────────────────────────────────────────────────────
// One row per duty, upserted by id — same pattern as /troops and
// /patrols. This replaces the old app_config 'duties' key, which stored
// the entire duty list as one JSON blob that got overwritten wholesale
// on every unrelated save from any device (see migrateSchema comment).
// Per-record writes mean two devices logging different duties at the
// same time can never wipe each other out.
app.get('/duties', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM duties ORDER BY date DESC, start_time DESC');
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

app.post('/duties', async (req, res) => {
  try {
    const { id, dutySeq, date, logicalDate, type, postId, postName, startTime, durationHours, troops, remarks, adminOverride, replacements, createdAt, modifiedAt, cancelled, cancelledAt, shiftIdx, shiftIdxCount, dutyId } = req.body;
    if (!isValidId(id)) return res.status(400).json({ error: 'Invalid duty id.' });
    if (!Array.isArray(troops) || !troops.every(t => typeof t === 'string' && t.length <= 100)) {
      return res.status(400).json({ error: 'Invalid troops list.' });
    }
    await pool.query(
      `INSERT INTO duties (id, duty_seq, date, logical_date, type, post_id, post_name, start_time, duration_hours, troops, remarks, admin_override, replacements, created_at, modified_at, cancelled, cancelled_at, shift_idx, shift_idx_count, duty_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
       ON CONFLICT (id) DO UPDATE
         SET duty_seq=$2, date=$3, logical_date=$4, type=$5, post_id=$6, post_name=$7, start_time=$8,
             duration_hours=$9, troops=$10, remarks=$11, admin_override=$12, replacements=$13,
             modified_at=$15, cancelled=$16, cancelled_at=$17, shift_idx=$18, shift_idx_count=$19, duty_id=$20`,
      [id, (Number.isFinite(parseInt(dutySeq)) ? parseInt(dutySeq) : null), date || null, logicalDate || date || null, clip(type || '', 50),
       postId || null, clip(postName || '', 100), startTime || null, parseFloat(durationHours) || null, JSON.stringify(troops || []), clip(remarks || '', 5000),
       !!adminOverride, JSON.stringify(replacements || []), createdAt || new Date().toISOString(), modifiedAt || new Date().toISOString(), !!cancelled,
       cancelledAt || null, (Number.isFinite(parseInt(shiftIdx)) ? parseInt(shiftIdx) : null), (Number.isFinite(parseInt(shiftIdxCount)) ? parseInt(shiftIdxCount) : null), clip(dutyId || '', 50)]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

app.delete('/duties/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM duties WHERE id = $1', [req.params.id]);
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

// ── FACTORY RESET ───────────────────────────────────────────────────
// Lets the main device wipe the shared database and start fresh. Gated
// two ways: only the main device may call it (same rule as deactivating
// other devices), AND it requires re-entering the master key even though
// the caller already has a valid session — a destructive, irreversible,
// all-devices-affected action deserves its own fresh confirmation rather
// than riding on whatever session happened to already be open. Reuses
// the same bad-key throttling as /login and /emergency-takeover.
//
// scope 'data' — clears troops (including archived), patrols, patrol
//                drafts, duty records, duty drafts, contingency
//                exclusion groups, and the audit log. Unit settings,
//                patrol/duty type lists, sectors/routes, duty posts,
//                and the security PIN are left untouched.
// scope 'full' — everything 'data' does, PLUS unit settings, all
//                configuration lists, and the security PIN — a true
//                factory-fresh state.
//
// Signed-in devices (sessions) are never touched by either scope — a
// data reset shouldn't sign anyone out of the app itself.
app.post('/factory-reset', async (req, res) => {
  try {
    if (!req.isMain) {
      return res.status(403).json({ error: 'Only the main device can reset all data.' });
    }
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const blockEntry = _badKeyBlocks.get(ip);
    if (blockEntry && now < blockEntry.until) {
      return res.status(403).json({ error: 'Too many invalid attempts. Blocked temporarily.' });
    }
    const masterKey = (req.body && req.body.masterKey) || '';
    if (!safeCompare(masterKey, API_KEY)) {
      console.warn('Rejected factory reset with invalid master key from IP:', ip);
      const rec = _badKeyFails.get(ip) || { count: 0, start: now };
      if (now - rec.start > BAD_KEY_WINDOW_MS) { rec.count = 0; rec.start = now; }
      rec.count++;
      _badKeyFails.set(ip, rec);
      if (rec.count >= BAD_KEY_MAX) {
        _badKeyBlocks.set(ip, { until: now + BAD_KEY_BLOCK_MS });
        _badKeyFails.delete(ip);
        console.warn('IP temporarily blocked for repeated invalid factory-reset attempts:', ip);
      }
      return res.status(401).json({ error: 'Incorrect master key.' });
    }
    const scope = (req.body && req.body.scope === 'full') ? 'full' : 'data';
    await pool.query('DELETE FROM patrols');
    await pool.query('DELETE FROM troops');
    await pool.query(`DELETE FROM app_config WHERE key IN ('drafts','dutyContingency','dutyDrafts')`);
    await pool.query('DELETE FROM duties');
    await pool.query(`INSERT INTO app_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`, ['counter', JSON.stringify(1)]);
    await pool.query(`INSERT INTO app_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`, ['dutyCounter', JSON.stringify(1)]);
    if (scope === 'full') {
      await pool.query(`DELETE FROM app_config WHERE key IN ('settings','config','security')`);
    }
    await pool.query('DELETE FROM audit_log');
    await pool.query(
      'INSERT INTO audit_log (ts, msg) VALUES ($1, $2)',
      [new Date().toISOString(), clip(`FACTORY RESET performed (${scope === 'full' ? 'full — including settings, config and PIN' : 'operational data only — settings, config and PIN kept'}) from IP ${ip}.`, 500)]
    );
    res.json({ ok: true, scope });
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
