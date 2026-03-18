// ── CLIENT-SIDE CRYPTO ─────────────────────────────────
// All encryption/decryption happens here — server never sees plaintext
// Uses Web Crypto API (AES-256-GCM + PBKDF2)

const enc = new TextEncoder();
const dec = new TextDecoder();

const b64  = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const ub64 = (s)   => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// ── KEY DERIVATION ────────────────────────────────────
export async function deriveMasterKey(masterPassword, saltB64) {
  const salt        = ub64(saltB64);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(masterPassword), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Generate new random salt (for first master password setup)
export function generateSalt() {
  return b64(crypto.getRandomValues(new Uint8Array(16)));
}

// ── VERIFIER (proves master pw is correct without sending pw to server) ──
const VERIFIER_PLAINTEXT = 'vault-master-key-verifier-v1';

export async function createMasterVerifier(masterKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    masterKey,
    enc.encode(VERIFIER_PLAINTEXT)
  );
  return JSON.stringify({ iv: b64(iv), ct: b64(new Uint8Array(ct)) });
}

export async function verifyMasterKey(masterKey, verifierJson) {
  try {
    const { iv, ct } = JSON.parse(verifierJson);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ub64(iv) },
      masterKey,
      ub64(ct)
    );
    return dec.decode(pt) === VERIFIER_PLAINTEXT;
  } catch {
    return false;
  }
}

// ── ENTRY ENCRYPTION / DECRYPTION ────────────────────
export async function encryptEntry(entryObj, masterKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    masterKey,
    enc.encode(JSON.stringify(entryObj))
  );
  return {
    encrypted_payload: b64(new Uint8Array(ct)),
    iv: b64(iv),
  };
}

export async function decryptEntry(encrypted_payload, ivB64, masterKey) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ub64(ivB64) },
    masterKey,
    ub64(encrypted_payload)
  );
  return JSON.parse(dec.decode(pt));
}

// ── RECOVERY KEY ──────────────────────────────────────
export function generateRecoveryKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  const hex   = Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
  // Format as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
  return hex.toUpperCase().match(/.{1,8}/g).join('-');
}

// Hash recovery key client-side before sending (bcrypt on server is the real store)
// We send the raw key to server which hashes it — just ensure we trim/uppercase
export function normaliseRecoveryKey(key) {
  return key.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
}

// ── PASSWORD STRENGTH ────────────────────────────────
export function passwordStrength(pw) {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 14) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const levels = [
    { label: 'Very Weak', color: '#ff5f5f', pct: 10 },
    { label: 'Weak',      color: '#ff8c42', pct: 28 },
    { label: 'Fair',      color: '#ffd166', pct: 52 },
    { label: 'Strong',    color: '#06d6a0', pct: 78 },
    { label: 'Very Strong',color:'#3dd68c', pct: 100 },
  ];
  return levels[Math.min(score, 4)];
}

// ── PASSWORD GENERATOR ────────────────────────────────
export function generatePassword(length = 20, upper = true, numbers = true, symbols = true) {
  let chars = 'abcdefghijklmnopqrstuvwxyz';
  if (upper)   chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (numbers) chars += '0123456789';
  if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const arr = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(arr).map(v => chars[v % chars.length]).join('');
}
