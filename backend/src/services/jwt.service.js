const jwt  = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { query } = require('../config/database');

const sign = (payload, secret, expiresIn) =>
  jwt.sign(payload, secret, { expiresIn, jwtid: uuidv4() });

// Short-lived access token
exports.signAccess = (userId, email) =>
  sign({ sub: userId, email, type: 'access' },
       process.env.JWT_SECRET,
       process.env.JWT_EXPIRES_IN || '15m');

// Intermediate token after password check — awaiting 2FA
exports.signPre2FA = (userId, email) =>
  sign({ sub: userId, email, type: 'pre2fa' },
       process.env.JWT_SECRET, '10m');

// Long-lived refresh token stored in DB
exports.signRefresh = async (userId, ip, userAgent) => {
  const token    = sign({ sub: userId, type: 'refresh' },
                         process.env.JWT_REFRESH_SECRET,
                         process.env.JWT_REFRESH_EXPIRES_IN || '7d');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await query(
    `INSERT INTO sessions (user_id, refresh_token, ip_address, user_agent, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, token, ip, userAgent, expiresAt]
  );

  return token;
};

exports.verifyAccess = (token) =>
  jwt.verify(token, process.env.JWT_SECRET);

exports.verifyRefresh = (token) =>
  jwt.verify(token, process.env.JWT_REFRESH_SECRET);

exports.revokeSession = (token) =>
  query(`UPDATE sessions SET is_active = FALSE WHERE refresh_token = $1`, [token]);

exports.revokeAllUserSessions = (userId) =>
  query(`UPDATE sessions SET is_active = FALSE WHERE user_id = $1`, [userId]);
