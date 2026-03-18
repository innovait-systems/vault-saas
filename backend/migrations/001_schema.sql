-- ═══════════════════════════════════════════════════
--  VAULT SAAS — PostgreSQL Schema
--  Run: psql $DATABASE_URL -f migrations/001_schema.sql
-- ═══════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── USERS ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT NOT NULL,          -- bcrypt hash of login password
  is_verified         BOOLEAN DEFAULT FALSE,
  is_active           BOOLEAN DEFAULT TRUE,

  -- Master password (never stored — only a verification hash + encrypted vault key)
  master_password_set BOOLEAN DEFAULT FALSE,
  master_key_salt     TEXT,                   -- PBKDF2 salt for master key derivation
  master_key_verifier TEXT,                   -- AES-GCM encrypted test blob to verify master pw

  -- 2FA
  totp_secret         TEXT,                   -- encrypted TOTP secret
  totp_enabled        BOOLEAN DEFAULT FALSE,
  email_2fa_enabled   BOOLEAN DEFAULT TRUE,   -- email OTP always available as fallback

  -- Recovery
  recovery_key_hash   TEXT,                   -- bcrypt hash of recovery key (shown once at setup)

  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW(),
  last_login_at       TIMESTAMPTZ
);

-- ─── OTP CODES (email verification, 2FA, reset) ──────
CREATE TABLE IF NOT EXISTS otp_codes (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,               -- also store email for pre-auth flows
  purpose     TEXT NOT NULL,               -- 'verify_email' | 'login_2fa' | 'reset_master' | 'reset_password'
  code_hash   TEXT NOT NULL,               -- bcrypt hash of the 6-digit code
  attempts    INT DEFAULT 0,
  used        BOOLEAN DEFAULT FALSE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ─── SESSIONS ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
  refresh_token TEXT UNIQUE NOT NULL,
  ip_address    TEXT,
  user_agent    TEXT,
  is_active     BOOLEAN DEFAULT TRUE,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ─── VAULT ENTRIES ────────────────────────────────────
CREATE TABLE IF NOT EXISTS vault_entries (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
  type          TEXT NOT NULL CHECK (type IN ('password','apikey','ssh','env')),

  -- All sensitive fields are AES-256-GCM encrypted client-side with master key
  encrypted_payload  TEXT NOT NULL,   -- JSON blob: {name,user,secret,url,notes} encrypted
  iv                 TEXT NOT NULL,   -- AES-GCM IV (base64)
  name_preview       TEXT,            -- plaintext name for search (non-sensitive label only)

  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ─── AUDIT LOG ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  event       TEXT NOT NULL,           -- 'login' | 'entry_add' | 'entry_delete' | 'master_reset' etc.
  ip_address  TEXT,
  meta        JSONB,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ─── INDEXES ──────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_vault_user    ON vault_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_otp_email     ON otp_codes(email, purpose);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);

-- ─── AUTO-UPDATE updated_at ───────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
  BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER vault_updated_at
  BEFORE UPDATE ON vault_entries FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Done
SELECT 'Schema created successfully' AS status;
