const { query } = require('../config/database');

const audit = (userId, event, ip, meta = {}) =>
  query(`INSERT INTO audit_log (user_id, event, ip_address, meta) VALUES ($1,$2,$3,$4)`,
        [userId, event, ip, JSON.stringify(meta)]);

// ── GET ALL ENTRIES ────────────────────────────────────
// Server returns encrypted payloads — client decrypts with master key
exports.getEntries = async (req, res) => {
  try {
    const result = await query(
      `SELECT id, type, encrypted_payload, iv, name_preview, created_at, updated_at
       FROM vault_entries WHERE user_id = $1 ORDER BY updated_at DESC`,
      [req.user.id]
    );
    res.json({ entries: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load vault.' });
  }
};

// ── CREATE ENTRY ──────────────────────────────────────
exports.createEntry = async (req, res) => {
  try {
    const { type, encrypted_payload, iv, name_preview } = req.body;
    const VALID_TYPES = ['password', 'apikey', 'ssh', 'env'];

    if (!VALID_TYPES.includes(type)) return res.status(400).json({ error: 'Invalid type.' });
    if (!encrypted_payload || !iv)   return res.status(400).json({ error: 'Encrypted payload and IV required.' });

    const result = await query(
      `INSERT INTO vault_entries (user_id, type, encrypted_payload, iv, name_preview)
       VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
      [req.user.id, type, encrypted_payload, iv, name_preview || null]
    );

    await audit(req.user.id, 'entry_created', req.ip, { type });
    res.status(201).json({ entry: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create entry.' });
  }
};

// ── UPDATE ENTRY ──────────────────────────────────────
exports.updateEntry = async (req, res) => {
  try {
    const { id } = req.params;
    const { encrypted_payload, iv, name_preview } = req.body;

    const result = await query(
      `UPDATE vault_entries
       SET encrypted_payload = $1, iv = $2, name_preview = $3
       WHERE id = $4 AND user_id = $5
       RETURNING id, updated_at`,
      [encrypted_payload, iv, name_preview, id, req.user.id]
    );

    if (!result.rows[0]) return res.status(404).json({ error: 'Entry not found.' });
    await audit(req.user.id, 'entry_updated', req.ip, { entryId: id });
    res.json({ entry: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update entry.' });
  }
};

// ── DELETE ENTRY ──────────────────────────────────────
exports.deleteEntry = async (req, res) => {
  try {
    const { id } = req.params;
    const result = await query(
      `DELETE FROM vault_entries WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Entry not found.' });
    await audit(req.user.id, 'entry_deleted', req.ip, { entryId: id });
    res.json({ message: 'Entry deleted.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete entry.' });
  }
};

// ── BULK REPLACE (for master password re-encryption) ──
// When master password is reset, client re-encrypts all entries with new key and bulk-replaces
exports.bulkReplace = async (req, res) => {
  try {
    const { entries } = req.body;
    if (!Array.isArray(entries)) return res.status(400).json({ error: 'entries must be an array.' });

    const client = await require('../config/database').getClient();
    try {
      await client.query('BEGIN');
      await client.query(`DELETE FROM vault_entries WHERE user_id = $1`, [req.user.id]);
      for (const e of entries) {
        await client.query(
          `INSERT INTO vault_entries (user_id, type, encrypted_payload, iv, name_preview)
           VALUES ($1,$2,$3,$4,$5)`,
          [req.user.id, e.type, e.encrypted_payload, e.iv, e.name_preview || null]
        );
      }
      await client.query('COMMIT');
      await audit(req.user.id, 'vault_bulk_replaced', req.ip, { count: entries.length });
      res.json({ message: `Vault re-encrypted with ${entries.length} entries.` });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    res.status(500).json({ error: 'Bulk replace failed.' });
  }
};
