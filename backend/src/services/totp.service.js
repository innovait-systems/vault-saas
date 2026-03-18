const { TOTP, Secret } = require('otpauth');
const QRCode = require('qrcode');

const ISSUER = process.env.TOTP_ISSUER || 'VaultApp';

// Generate a new TOTP secret for a user
function generateTOTPSecret(email) {
  const secret = new Secret({ size: 20 });
  const totp = new TOTP({
    issuer: ISSUER,
    label:  email,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret,
  });

  return {
    secret: secret.base32,       // Store this (should be encrypted in DB)
    otpauthUrl: totp.toString(), // For QR code generation
  };
}

// Generate QR code data URI from otpauth URL
async function generateQRCode(otpauthUrl) {
  return QRCode.toDataURL(otpauthUrl, {
    width: 256,
    color: { dark: '#f0c040', light: '#13161c' },
  });
}

// Verify a TOTP token — allows ±1 window for clock drift
function verifyTOTP(secret, token) {
  const totp = new TOTP({
    issuer: ISSUER,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secret),
  });

  const delta = totp.validate({ token: String(token), window: 1 });
  return delta !== null; // null = invalid
}

module.exports = { generateTOTPSecret, generateQRCode, verifyTOTP };
