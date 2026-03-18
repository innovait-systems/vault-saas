const { verifyAccess } = require('../services/jwt.service');
const { query }        = require('../config/database');

exports.requireAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided.' });
    }

    const token   = header.split(' ')[1];
    const payload = verifyAccess(token);

    if (payload.type !== 'access') {
      return res.status(401).json({ error: 'Invalid token type.' });
    }

    // Load user from DB
    const result = await query(
      `SELECT id, email, is_verified, is_active, totp_enabled,
              email_2fa_enabled, master_password_set
       FROM users WHERE id = $1`,
      [payload.sub]
    );

    if (!result.rows[0] || !result.rows[0].is_active) {
      return res.status(401).json({ error: 'Account not found or deactivated.' });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired.', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token.' });
  }
};

exports.requirePre2FA = (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token.' });
    const payload = verifyAccess(header.split(' ')[1]);
    if (payload.type !== 'pre2fa') return res.status(401).json({ error: 'Invalid token type.' });
    req.preAuth = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired pre-auth token.' });
  }
};
