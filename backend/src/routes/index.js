const express = require('express');
const router  = express.Router();
const auth    = require('../controllers/auth.controller');
const vault   = require('../controllers/vault.controller');
const { requireAuth, requirePre2FA } = require('../middleware/auth.middleware');

// ── AUTH ──────────────────────────────────────────────
router.post('/auth/register',           auth.register);
router.post('/auth/verify-email',       auth.verifyEmail);
router.post('/auth/resend-verification',auth.resendVerification);

router.post('/auth/login',              auth.loginStep1);
router.post('/auth/login/2fa',          requirePre2FA, auth.loginStep2);

router.post('/auth/refresh',            auth.refreshToken);
router.post('/auth/logout',             auth.logout);

router.post('/auth/forgot-password',    auth.forgotLoginPassword);
router.post('/auth/reset-password',     auth.resetLoginPassword);

// ── MASTER PASSWORD ───────────────────────────────────
router.get ('/auth/master-salt',        requireAuth, auth.getMasterKeySalt);
router.post('/auth/master-setup',       requireAuth, auth.setMasterPassword);
router.post('/auth/master-reset/init',  requireAuth, auth.forgotMasterStep1);
router.post('/auth/master-reset/verify',requireAuth, auth.forgotMasterStep2);

// ── TOTP SETUP ────────────────────────────────────────
router.post('/auth/totp/init',    requireAuth, auth.setupTOTPInit);
router.post('/auth/totp/confirm', requireAuth, auth.setupTOTPConfirm);
router.delete('/auth/totp',       requireAuth, auth.disableTOTP);

// ── PROFILE ───────────────────────────────────────────
router.get('/auth/me', requireAuth, auth.getProfile);

// ── VAULT (all require full auth) ─────────────────────
router.get   ('/vault',          requireAuth, vault.getEntries);
router.post  ('/vault',          requireAuth, vault.createEntry);
router.put   ('/vault/:id',      requireAuth, vault.updateEntry);
router.delete('/vault/:id',      requireAuth, vault.deleteEntry);
router.post  ('/vault/bulk',     requireAuth, vault.bulkReplace);

module.exports = router;
