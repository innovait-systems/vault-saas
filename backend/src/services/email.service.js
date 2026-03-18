const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  debug:  true,
  logger: true,
});

// ── BASE TEMPLATE ──────────────────────────────────────
const base = (content) => `
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { margin:0; padding:0; background:#0d0f12; font-family:'Segoe UI',Arial,sans-serif; }
  .wrap { max-width:520px; margin:40px auto; background:#13161c; border-radius:16px;
          border:1px solid #252b3a; overflow:hidden; }
  .header { background:#13161c; padding:32px 40px 24px; border-bottom:1px solid #252b3a;
            text-align:center; }
  .logo { font-size:28px; font-weight:800; color:#edf0f7; letter-spacing:-.02em; }
  .logo span { color:#f0c040; }
  .body { padding:32px 40px; color:#c8d0e0; font-size:15px; line-height:1.7; }
  .otp-box { background:#1a1e27; border:1px solid #2e3648; border-radius:12px;
             text-align:center; padding:28px; margin:24px 0; }
  .otp-code { font-size:42px; font-weight:800; color:#f0c040; letter-spacing:10px;
              font-family:'Courier New',monospace; }
  .otp-expire { font-size:12px; color:#5c6680; margin-top:8px; font-family:monospace; }
  .btn { display:inline-block; background:#f0c040; color:#0d0f12; padding:12px 28px;
         border-radius:8px; font-weight:700; text-decoration:none; font-size:15px; }
  .recovery-box { background:#1a1e27; border:1px solid #3dd68c44; border-radius:12px;
                  padding:20px; margin:20px 0; font-family:monospace; font-size:13px;
                  color:#3dd68c; word-break:break-all; text-align:center; letter-spacing:2px; }
  .warn { background:#ff5f5f11; border:1px solid #ff5f5f44; border-radius:8px;
          padding:14px 18px; color:#ff8080; font-size:13px; margin-top:16px; }
  .footer { padding:20px 40px; border-top:1px solid #252b3a; text-align:center;
            font-size:12px; color:#5c6680; }
</style></head><body>
<div class="wrap">
  <div class="header"><div class="logo">Va<span>ult</span> 🔐</div></div>
  <div class="body">${content}</div>
  <div class="footer">© ${new Date().getFullYear()} Vault · Secure Credential Manager<br>
  If you didn't request this, you can safely ignore this email.</div>
</div></body></html>`;

// ── SEND HELPERS ───────────────────────────────────────
const send = (to, subject, html) =>
  transporter.sendMail({ from: process.env.EMAIL_FROM, to, subject, html });

// ── EMAIL TEMPLATES ────────────────────────────────────

exports.sendVerificationOTP = (email, otp) =>
  send(email, '🔐 Verify your Vault account', base(`
    <p>Welcome to <strong>Vault</strong>! Please verify your email address to activate your account.</p>
    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-expire">Expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes</div>
    </div>
    <p>Enter this code on the verification page to complete your registration.</p>
    <div class="warn">⚠️ Never share this code with anyone. Vault staff will never ask for it.</div>
  `));

exports.sendLoginOTP = (email, otp) =>
  send(email, '🔑 Your Vault login code', base(`
    <p>A login attempt was made for your Vault account. Use the code below to complete sign-in.</p>
    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-expire">Expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes</div>
    </div>
    <div class="warn">⚠️ If you did not attempt to log in, your password may be compromised. Change it immediately.</div>
  `));

exports.sendMasterResetOTP = (email, otp) =>
  send(email, '⚠️ Master Password Reset — Vault', base(`
    <p>You requested to reset your <strong>master password</strong>. This will <strong>re-encrypt your entire vault</strong>.</p>
    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-expire">Expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes</div>
    </div>
    <div class="warn">⚠️ <strong>WARNING:</strong> Resetting your master password will permanently delete all stored credentials unless you have your Recovery Key. This action cannot be undone.</div>
  `));

exports.sendPasswordResetOTP = (email, otp) =>
  send(email, '🔄 Reset your Vault login password', base(`
    <p>You requested a login password reset for your Vault account.</p>
    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-expire">Expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes</div>
    </div>
  `));

exports.sendRecoveryKey = (email, recoveryKey) =>
  send(email, '🛡️ Your Vault Recovery Key — Save This Now!', base(`
    <p>Your master password has been set. Here is your <strong>Recovery Key</strong> — the only way to recover your vault if you forget your master password.</p>
    <div class="recovery-box">${recoveryKey}</div>
    <div class="warn">
      ⚠️ <strong>IMPORTANT — Read carefully:</strong><br><br>
      • Store this key somewhere <strong>safe and offline</strong> (printed paper, secure notes app)<br>
      • This key is shown <strong>only once</strong> and is NOT stored on our servers<br>
      • Without this key, a forgotten master password means <strong>permanent loss of all credentials</strong><br>
      • Do NOT store this in your Vault itself
    </div>
  `));

exports.sendWelcome = (email) =>
  send(email, '👋 Welcome to Vault!', base(`
    <p>Your account is verified and ready to go!</p>
    <p>Vault uses <strong>AES-256-GCM end-to-end encryption</strong> — your credentials are encrypted before they leave your device. Even we cannot read them.</p>
    <p style="text-align:center;margin-top:28px">
      <a class="btn" href="${process.env.FRONTEND_URL}/login">Open Vault →</a>
    </p>
  `));
