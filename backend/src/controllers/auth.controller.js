const bcrypt  = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { query }      = require('../config/database');
const emailSvc  = require('../services/email.service');
const otpSvc    = require('../services/otp.service');
const totpSvc   = require('../services/totp.service');
const jwtSvc    = require('../services/jwt.service');

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12');

const audit = (userId, event, ip, meta = {}) =>
  query(`INSERT INTO audit_log (user_id, event, ip_address, meta) VALUES ($1,$2,$3,$4)`,
        [userId, event, ip, JSON.stringify(meta)]);

// ── REGISTER ──────────────────────────────────────────
exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const existing = await query(`SELECT id FROM users WHERE email = $1`, [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = await query(
      `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email`,
      [email.toLowerCase(), passwordHash]
    );

    const user = result.rows[0];
    const otp  = await otpSvc.createOTP(user.email, 'verify_email', user.id);
    await emailSvc.sendVerificationOTP(user.email, otp);
    await audit(user.id, 'register', req.ip);

    res.status(201).json({ message: 'Account created. Check your email for the verification code.' });
  } catch (err) {
    console.error('register:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
};

// ── VERIFY EMAIL ──────────────────────────────────────
exports.verifyEmail = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const { valid, error } = await otpSvc.verifyOTP(email.toLowerCase(), 'verify_email', otp);
    if (!valid) return res.status(400).json({ error });

    await query(`UPDATE users SET is_verified = TRUE WHERE email = $1`, [email.toLowerCase()]);
    const user = (await query(`SELECT id FROM users WHERE email = $1`, [email.toLowerCase()])).rows[0];
    await emailSvc.sendWelcome(email);
    await audit(user.id, 'verify_email', req.ip);

    res.json({ message: 'Email verified! You can now log in.' });
  } catch (err) {
    console.error('verifyEmail:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
};

// ── RESEND VERIFICATION ───────────────────────────────
exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    const result = await query(`SELECT id, is_verified FROM users WHERE email = $1`, [email.toLowerCase()]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Account not found.' });
    if (result.rows[0].is_verified) return res.status(400).json({ error: 'Email already verified.' });

    const otp = await otpSvc.createOTP(email.toLowerCase(), 'verify_email', result.rows[0].id);
    await emailSvc.sendVerificationOTP(email, otp);
    res.json({ message: 'Verification code resent.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to resend code.' });
  }
};

// ── LOGIN — STEP 1 (password check) ──────────────────
exports.loginStep1 = async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await query(
      `SELECT id, email, password_hash, is_verified, is_active,
              totp_enabled, email_2fa_enabled
       FROM users WHERE email = $1`,
      [email.toLowerCase()]
    );

    const user = result.rows[0];
    // Always hash compare to prevent timing attacks
    const dummyHash = '$2a$12$dummy.hash.to.prevent.timing.attacks.padding';
    const valid = user ? await bcrypt.compare(password, user.password_hash)
                       : await bcrypt.compare(password, dummyHash);

    if (!valid || !user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    if (!user.is_verified) {
      return res.status(403).json({ error: 'Please verify your email first.', code: 'EMAIL_UNVERIFIED' });
    }
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account deactivated.' });
    }

    // Issue pre-2FA token
    const pre2faToken = jwtSvc.signPre2FA(user.id, user.email);

    // Determine 2FA method(s) available
    const methods = [];
    if (user.totp_enabled) methods.push('totp');
    if (user.email_2fa_enabled) methods.push('email');

    if (methods.length === 0) {
      // No 2FA configured — issue full tokens directly
      const accessToken  = jwtSvc.signAccess(user.id, user.email);
      const refreshToken = await jwtSvc.signRefresh(user.id, req.ip, req.headers['user-agent']);
      await query(`UPDATE users SET last_login_at = NOW() WHERE id = $1`, [user.id]);
      await audit(user.id, 'login', req.ip, { method: 'password_only' });
      return res.json({ accessToken, refreshToken, requires2FA: false });
    }

    // If email 2FA is enabled, automatically send OTP
    if (user.email_2fa_enabled) {
      const otp = await otpSvc.createOTP(user.email, 'login_2fa', user.id);
      await emailSvc.sendLoginOTP(user.email, otp);
    }

    res.json({ pre2faToken, requires2FA: true, methods });
  } catch (err) {
    console.error('loginStep1:', err);
    res.status(500).json({ error: 'Login failed.' });
  }
};

// ── LOGIN — STEP 2 (2FA verify) ───────────────────────
exports.loginStep2 = async (req, res) => {
  try {
    const { method, code } = req.body;
    const { sub: userId, email } = req.preAuth;

    let verified = false;

    if (method === 'totp') {
      const userResult = await query(`SELECT totp_secret, totp_enabled FROM users WHERE id = $1`, [userId]);
      const u = userResult.rows[0];
      if (!u?.totp_enabled) return res.status(400).json({ error: 'TOTP not enabled.' });
      verified = totpSvc.verifyTOTP(u.totp_secret, code);
      if (!verified) return res.status(401).json({ error: 'Invalid authenticator code.' });

    } else if (method === 'email') {
      const { valid, error } = await otpSvc.verifyOTP(email, 'login_2fa', code);
      if (!valid) return res.status(401).json({ error });
      verified = true;
    } else {
      return res.status(400).json({ error: 'Invalid 2FA method.' });
    }

    const accessToken  = jwtSvc.signAccess(userId, email);
    const refreshToken = await jwtSvc.signRefresh(userId, req.ip, req.headers['user-agent']);
    await query(`UPDATE users SET last_login_at = NOW() WHERE id = $1`, [userId]);
    await audit(userId, 'login', req.ip, { method });

    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error('loginStep2:', err);
    res.status(500).json({ error: '2FA verification failed.' });
  }
};

// ── REFRESH TOKEN ─────────────────────────────────────
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required.' });

    const payload = jwtSvc.verifyRefresh(refreshToken);
    const session = await query(
      `SELECT * FROM sessions WHERE refresh_token = $1 AND is_active = TRUE AND expires_at > NOW()`,
      [refreshToken]
    );
    if (!session.rows[0]) return res.status(401).json({ error: 'Invalid or expired session.' });

    const user = await query(`SELECT id, email, is_active FROM users WHERE id = $1`, [payload.sub]);
    if (!user.rows[0]?.is_active) return res.status(401).json({ error: 'Account inactive.' });

    const newAccess  = jwtSvc.signAccess(user.rows[0].id, user.rows[0].email);
    const newRefresh = await jwtSvc.signRefresh(user.rows[0].id, req.ip, req.headers['user-agent']);
    await jwtSvc.revokeSession(refreshToken); // Rotate refresh token

    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch (err) {
    res.status(401).json({ error: 'Token refresh failed.' });
  }
};

// ── LOGOUT ────────────────────────────────────────────
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) await jwtSvc.revokeSession(refreshToken);
    res.json({ message: 'Logged out.' });
  } catch {
    res.json({ message: 'Logged out.' });
  }
};

// ── SET MASTER PASSWORD ───────────────────────────────
// Called once after first login — master pw never sent to server in usable form
// Server only receives an AES-GCM encrypted verifier blob to confirm future master pw entries
exports.setMasterPassword = async (req, res) => {
  try {
    const { masterKeySalt, masterKeyVerifier, recoveryKeyHash } = req.body;
    // masterKeySalt:    base64 PBKDF2 salt used client-side to derive AES key from master pw
    // masterKeyVerifier: base64 AES-GCM encrypted known plaintext — used to verify master pw on unlock
    // recoveryKeyHash:  bcrypt hash of the recovery key (generated client-side)

    if (!masterKeySalt || !masterKeyVerifier || !recoveryKeyHash) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    const user = req.user;
    if (user.master_password_set) {
      return res.status(409).json({ error: 'Master password already set. Use reset flow.' });
    }

    await query(
      `UPDATE users SET master_password_set = TRUE,
       master_key_salt = $1, master_key_verifier = $2, recovery_key_hash = $3
       WHERE id = $4`,
      [masterKeySalt, masterKeyVerifier, recoveryKeyHash, user.id]
    );

    await audit(user.id, 'master_password_set', req.ip);
    res.json({ message: 'Master password set successfully.' });
  } catch (err) {
    console.error('setMasterPassword:', err);
    res.status(500).json({ error: 'Failed to set master password.' });
  }
};

// ── GET MASTER KEY SALT ───────────────────────────────
// Client needs salt to re-derive the master key from the entered master password
exports.getMasterKeySalt = async (req, res) => {
  try {
    const result = await query(
      `SELECT master_key_salt, master_key_verifier, master_password_set FROM users WHERE id = $1`,
      [req.user.id]
    );
    const u = result.rows[0];
    if (!u.master_password_set) {
      return res.status(404).json({ error: 'Master password not set yet.', code: 'NO_MASTER' });
    }
    res.json({ masterKeySalt: u.master_key_salt, masterKeyVerifier: u.master_key_verifier });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch salt.' });
  }
};

// ── FORGOT MASTER PASSWORD — Step 1: request OTP ─────
exports.forgotMasterStep1 = async (req, res) => {
  try {
    const user = req.user;
    const otp  = await otpSvc.createOTP(user.email, 'reset_master', user.id);
    await emailSvc.sendMasterResetOTP(user.email, otp);
    await audit(user.id, 'master_reset_requested', req.ip);
    res.json({ message: 'Reset OTP sent to your email.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send reset OTP.' });
  }
};

// ── FORGOT MASTER PASSWORD — Step 2: verify OTP + set new master ─
exports.forgotMasterStep2 = async (req, res) => {
  try {
    const { otp, masterKeySalt, masterKeyVerifier, recoveryKeyHash, clearVault } = req.body;
    const user = req.user;

    const { valid, error } = await otpSvc.verifyOTP(user.email, 'reset_master', otp);
    if (!valid) return res.status(400).json({ error });

    // If clearVault=true, delete all entries (they are unrecoverable without old master pw)
    if (clearVault) {
      await query(`DELETE FROM vault_entries WHERE user_id = $1`, [user.id]);
    }

    await query(
      `UPDATE users SET master_key_salt = $1, master_key_verifier = $2,
       recovery_key_hash = $3 WHERE id = $4`,
      [masterKeySalt, masterKeyVerifier, recoveryKeyHash, user.id]
    );

    await audit(user.id, 'master_password_reset', req.ip, { vaultCleared: !!clearVault });
    res.json({ message: 'Master password reset successfully.' });
  } catch (err) {
    console.error('forgotMasterStep2:', err);
    res.status(500).json({ error: 'Master password reset failed.' });
  }
};

// ── FORGOT LOGIN PASSWORD ─────────────────────────────
exports.forgotLoginPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const result = await query(`SELECT id FROM users WHERE email = $1 AND is_verified = TRUE`, [email.toLowerCase()]);
    // Always respond OK to prevent email enumeration
    if (result.rows[0]) {
      const otp = await otpSvc.createOTP(email.toLowerCase(), 'reset_password', result.rows[0].id);
      await emailSvc.sendPasswordResetOTP(email, otp);
    }
    res.json({ message: 'If an account exists, a reset code has been sent.' });
  } catch (err) {
    res.status(500).json({ error: 'Reset request failed.' });
  }
};

exports.resetLoginPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const { valid, error } = await otpSvc.verifyOTP(email.toLowerCase(), 'reset_password', otp);
    if (!valid) return res.status(400).json({ error });

    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    const result = await query(
      `UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id`,
      [hash, email.toLowerCase()]
    );

    await jwtSvc.revokeAllUserSessions(result.rows[0].id);
    await audit(result.rows[0].id, 'login_password_reset', req.ip);
    res.json({ message: 'Password reset. Please log in with your new password.' });
  } catch (err) {
    res.status(500).json({ error: 'Password reset failed.' });
  }
};

// ── TOTP SETUP ────────────────────────────────────────
exports.setupTOTPInit = async (req, res) => {
  try {
    const { secret, otpauthUrl } = totpSvc.generateTOTPSecret(req.user.email);
    const qrCode = await totpSvc.generateQRCode(otpauthUrl);
    // Store secret temporarily — confirmed only after user verifies a code
    await query(`UPDATE users SET totp_secret = $1 WHERE id = $2`, [secret, req.user.id]);
    res.json({ secret, qrCode });
  } catch (err) {
    res.status(500).json({ error: 'TOTP setup failed.' });
  }
};

exports.setupTOTPConfirm = async (req, res) => {
  try {
    const { code } = req.body;
    const result = await query(`SELECT totp_secret FROM users WHERE id = $1`, [req.user.id]);
    const secret = result.rows[0]?.totp_secret;
    if (!secret) return res.status(400).json({ error: 'TOTP not initialized.' });

    const valid = totpSvc.verifyTOTP(secret, code);
    if (!valid) return res.status(400).json({ error: 'Invalid code. Please try again.' });

    await query(`UPDATE users SET totp_enabled = TRUE WHERE id = $1`, [req.user.id]);
    await audit(req.user.id, 'totp_enabled', req.ip);
    res.json({ message: 'Authenticator app enabled successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'TOTP confirmation failed.' });
  }
};

exports.disableTOTP = async (req, res) => {
  try {
    await query(`UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1`, [req.user.id]);
    await audit(req.user.id, 'totp_disabled', req.ip);
    res.json({ message: 'Authenticator app disabled.' });
  } catch {
    res.status(500).json({ error: 'Failed to disable TOTP.' });
  }
};

// ── PROFILE ───────────────────────────────────────────
exports.getProfile = async (req, res) => {
  try {
    const result = await query(
      `SELECT id, email, is_verified, totp_enabled, email_2fa_enabled,
              master_password_set, created_at, last_login_at FROM users WHERE id = $1`,
      [req.user.id]
    );
    res.json({ user: result.rows[0] });
  } catch {
    res.status(500).json({ error: 'Failed to load profile.' });
  }
};
