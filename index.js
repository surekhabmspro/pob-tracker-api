const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── HEALTH ────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date() }));

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
    const { id, name, rank, unit, sn, status, notes } = req.body;
    await pool.query(
      `INSERT INTO troops (id, name, rank, unit, sn, status, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (id) DO UPDATE
         SET name=$2, rank=$3, unit=$4, sn=$5, status=$6, notes=$7`,
      [id, name, rank || '', unit || '', sn || '', status || 'available', notes || '']
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
    const { id, ptl_id, date, type, troops, area, duration, route, remarks } = req.body;
    await pool.query(
      `INSERT INTO patrols (id, ptl_id, date, type, troops, area, duration, route, remarks)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (id) DO UPDATE
         SET ptl_id=$2, date=$3, type=$4, troops=$5, area=$6,
             duration=$7, route=$8, remarks=$9`,
      [id, ptl_id || '', date, type || '', troops || [], area || '',
       parseFloat(duration) || null, route || '', remarks || '']
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
app.listen(PORT, () => {
  console.log(`POB Tracker API running on port ${PORT}`);
});
