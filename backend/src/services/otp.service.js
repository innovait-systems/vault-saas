const bcrypt = require('bcryptjs');
const { query } = require('../config/database');

const OTP_EXPIRES_MINUTES = parseInt(process.env.OTP_EXPIRES_MINUTES || '10');
const OTP_MAX_ATTEMPTS    = parseInt(process.env.OTP_MAX_ATTEMPTS    || '5');

// Generate a cryptographically secure 6-digit OTP
function generateOTP() {
  const arr = new Uint32Array(1);
  require('crypto').getRandomValues
    ? require('crypto').webcrypto.getRandomValues(arr)
    : (arr[0] = Math.floor(100000 + Math.random() * 900000));
  return String(100000 + (arr[0] % 900000)).padStart(6, '0');
}

// Create and store OTP — invalidates any previous OTPs for same email+purpose
async function createOTP(email, purpose, userId = null) {
  const otp      = generateOTP();
  const codeHash = await bcrypt.hash(otp, 10);
  const expiresAt = new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000);

  // Invalidate previous unused codes for same email+purpose
  await query(
    `UPDATE otp_codes SET used = TRUE
     WHERE email = $1 AND purpose = $2 AND used = FALSE`,
    [email, purpose]
  );

  await query(
    `INSERT INTO otp_codes (user_id, email, purpose, code_hash, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, email, purpose, codeHash, expiresAt]
  );

  return otp; // Return plaintext — only sent via email, never stored
}

// Verify OTP — returns { valid, error, otpRecord }
async function verifyOTP(email, purpose, code) {
  const result = await query(
    `SELECT * FROM otp_codes
     WHERE email = $1 AND purpose = $2 AND used = FALSE AND expires_at > NOW()
     ORDER BY created_at DESC LIMIT 1`,
    [email, purpose]
  );

  if (result.rows.length === 0) {
    return { valid: false, error: 'OTP not found or expired. Please request a new one.' };
  }

  const record = result.rows[0];

  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    await query(`UPDATE otp_codes SET used = TRUE WHERE id = $1`, [record.id]);
    return { valid: false, error: 'Too many failed attempts. Please request a new OTP.' };
  }

  const match = await bcrypt.compare(String(code), record.code_hash);

  if (!match) {
    await query(`UPDATE otp_codes SET attempts = attempts + 1 WHERE id = $1`, [record.id]);
    const remaining = OTP_MAX_ATTEMPTS - record.attempts - 1;
    return { valid: false, error: `Invalid code. ${remaining} attempt(s) remaining.` };
  }

  // Mark used
  await query(`UPDATE otp_codes SET used = TRUE WHERE id = $1`, [record.id]);
  return { valid: true, otpRecord: record };
}

module.exports = { createOTP, verifyOTP, generateOTP };
