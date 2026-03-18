# 🔐 Vault SaaS — Secure Credential Manager

A production-ready, end-to-end encrypted credential manager SaaS built with:
- **Backend**: Node.js + Express + PostgreSQL
- **Frontend**: Vanilla JS (zero dependencies, Web Crypto API)
- **Security**: AES-256-GCM, PBKDF2 (310k iterations), bcrypt, TOTP + Email 2FA

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        BROWSER                              │
│                                                             │
│  Master Password ──► PBKDF2 ──► AES-256 Key (in memory)    │
│                                        │                    │
│                              Encrypt/Decrypt entries        │
│                                        │                    │
│                              Encrypted blobs only ──► API   │
└─────────────────────────────────────────────────────────────┘
                                         │
┌─────────────────────────────────────────────────────────────┐
│                      EXPRESS API                            │
│                                                             │
│  ✅ Stores: encrypted_payload, iv, master_key_salt           │
│  ✅ Stores: master_key_verifier (AES-GCM test blob)         │
│  ✅ Stores: bcrypt(login_password), bcrypt(recovery_key)    │
│                                                             │
│  ❌ Never sees: master password, plaintext entries          │
│  ❌ Never sees: AES encryption key                          │
└─────────────────────────────────────────────────────────────┘
                                         │
┌─────────────────────────────────────────────────────────────┐
│                     POSTGRESQL                              │
│  users, vault_entries, otp_codes, sessions, audit_log       │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Design

### Zero-Knowledge Architecture
The server **never** has access to your plaintext credentials. Here's exactly what happens:

| Action | Client | Server |
|--------|--------|--------|
| Set master password | Derives AES-256 key via PBKDF2(password, salt, 310k) | Stores salt + AES-GCM verifier blob only |
| Add credential | AES-256-GCM encrypts entry with master key | Stores encrypted_payload + IV |
| Unlock vault | Derives key from master pw, verifies against blob | Returns encrypted blobs only |
| Master pw reset | Re-derives new key, re-encrypts all entries client-side | Replaces all encrypted blobs |

### Password Hashing
- **Login password**: bcrypt (12 rounds)
- **Recovery key**: SHA-256 client-side → bcrypt (12 rounds) server-side
- **OTP codes**: bcrypt (10 rounds), invalidated after use

### 2FA
- **TOTP**: HMAC-SHA1, 6 digits, 30s window, ±1 window drift tolerance (Google Authenticator compatible)
- **Email OTP**: 6-digit code, 10 minute expiry, max 5 attempts before invalidation
- Both available simultaneously; user chooses at login

### Rate Limiting
- Global: 100 req / 15 min
- Auth endpoints: 10 req / 15 min
- OTP brute force: max 5 attempts per code

### Master Password Recovery
Uses **Email OTP verification → vault re-encryption** approach:
1. User requests reset → OTP sent to verified email
2. User provides OTP + new master password
3. Client re-derives new AES key from new master password
4. All vault entries are re-encrypted client-side with new key
5. Server receives and stores new encrypted blobs (bulk replace, atomic transaction)
6. New recovery key generated and emailed

> ⚠️ If user has no recovery key and forgets master password, vault entries are permanently unrecoverable. This is by design — the server cannot decrypt them.

---

## Project Structure

```
vault-saas/
├── backend/
│   ├── src/
│   │   ├── server.js              # Express entry point
│   │   ├── config/
│   │   │   └── database.js        # PostgreSQL pool
│   │   ├── controllers/
│   │   │   ├── auth.controller.js # Register, login, 2FA, master pw
│   │   │   └── vault.controller.js# CRUD for encrypted entries
│   │   ├── middleware/
│   │   │   └── auth.middleware.js # JWT verification
│   │   ├── routes/
│   │   │   └── index.js           # All API routes
│   │   └── services/
│   │       ├── email.service.js   # Nodemailer + HTML templates
│   │       ├── otp.service.js     # Generate, hash, verify OTPs
│   │       ├── totp.service.js    # TOTP (Google Authenticator)
│   │       └── jwt.service.js     # Access + refresh tokens
│   ├── migrations/
│   │   └── 001_schema.sql         # Full PostgreSQL schema
│   ├── .env.example               # Environment variable template
│   ├── Dockerfile
│   └── package.json
│
├── frontend/
│   └── src/
│       └── index.html             # Complete SPA (no build step needed)
│
├── docker-compose.yml
└── README.md
```

---

## Quick Start

### Option A — Docker Compose (Recommended)

```bash
# 1. Clone and enter the project
git clone <your-repo> vault-saas
cd vault-saas

# 2. Set up backend environment
cp backend/.env.example backend/.env
# Edit backend/.env with your SMTP credentials

# 3. Start everything
docker compose up -d

# App running at:
#   Frontend: http://localhost:3000
#   API:      http://localhost:4000
```

### Option B — Manual Setup

#### Prerequisites
- Node.js 18+
- PostgreSQL 14+

#### 1. Database
```bash
# Create database
createdb vault_saas

# Run migrations
psql vault_saas -f backend/migrations/001_schema.sql
```

#### 2. Backend
```bash
cd backend
npm install
cp .env.example .env
# Edit .env — fill in DATABASE_URL and SMTP credentials
npm run dev
# API starts on http://localhost:4000
```

#### 3. Frontend
```bash
# No build step needed — open directly or serve with any static server
cd frontend/src

# Option 1: Python
python -m http.server 3000

# Option 2: Node
npx serve . -p 3000

# Option 3: Open index.html directly in browser
# (Change API const in index.html to http://localhost:4000/api)
```

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and fill in:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/vault_saas

# JWT — generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=<64-char-random-hex>
JWT_REFRESH_SECRET=<64-char-random-hex>

# SMTP (Gmail example — use App Password, not account password)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=your_16_char_app_password
EMAIL_FROM="Vault 🔐 <your@gmail.com>"

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3000
```

### Generating JWT secrets
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Gmail App Password Setup
1. Enable 2-Step Verification on your Google account
2. Go to Google Account → Security → App passwords
3. Generate a password for "Mail"
4. Use that 16-character password as `SMTP_PASS`

---

## API Reference

### Auth Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | None | Create account |
| POST | `/api/auth/verify-email` | None | Verify email with OTP |
| POST | `/api/auth/resend-verification` | None | Resend email OTP |
| POST | `/api/auth/login` | None | Step 1 — password check |
| POST | `/api/auth/login/2fa` | Pre-2FA token | Step 2 — 2FA verify |
| POST | `/api/auth/refresh` | None | Rotate refresh token |
| POST | `/api/auth/logout` | None | Revoke session |
| POST | `/api/auth/forgot-password` | None | Send login pw reset OTP |
| POST | `/api/auth/reset-password` | None | Reset login password |
| GET  | `/api/auth/me` | Bearer | Get profile |
| GET  | `/api/auth/master-salt` | Bearer | Get PBKDF2 salt + verifier |
| POST | `/api/auth/master-setup` | Bearer | Set master password |
| POST | `/api/auth/master-reset/init` | Bearer | Send master reset OTP |
| POST | `/api/auth/master-reset/verify` | Bearer | Reset master + re-encrypt |
| POST | `/api/auth/totp/init` | Bearer | Init TOTP setup (get QR) |
| POST | `/api/auth/totp/confirm` | Bearer | Confirm TOTP with code |
| DELETE | `/api/auth/totp` | Bearer | Disable TOTP |

### Vault Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/vault` | Bearer | Fetch all encrypted entries |
| POST | `/api/vault` | Bearer | Create encrypted entry |
| PUT | `/api/vault/:id` | Bearer | Update encrypted entry |
| DELETE | `/api/vault/:id` | Bearer | Delete entry |
| POST | `/api/vault/bulk` | Bearer | Bulk replace (master pw reset) |

### Request / Response Examples

**Register**
```json
POST /api/auth/register
{ "email": "user@example.com", "password": "SecurePass123!" }

→ 201 { "message": "Account created. Check your email..." }
```

**Login Step 1**
```json
POST /api/auth/login
{ "email": "user@example.com", "password": "SecurePass123!" }

→ 200 {
  "pre2faToken": "eyJ...",
  "requires2FA": true,
  "methods": ["totp", "email"]
}
```

**Login Step 2**
```json
POST /api/auth/login/2fa
Authorization: Bearer <pre2faToken>
{ "method": "email", "code": "847291" }

→ 200 { "accessToken": "eyJ...", "refreshToken": "eyJ..." }
```

**Create Vault Entry**
```json
POST /api/vault
Authorization: Bearer <accessToken>
{
  "type": "password",
  "encrypted_payload": "<base64-AES-GCM-ciphertext>",
  "iv": "<base64-IV>",
  "name_preview": "GitHub"
}
→ 201 { "entry": { "id": "uuid", "created_at": "..." } }
```

---

## Database Schema

```sql
users            — accounts, master key salt/verifier, 2FA config
otp_codes        — email OTPs (verify, 2FA, reset) with attempt tracking
sessions         — refresh tokens, IP, user agent
vault_entries    — encrypted payloads only (server blind)
audit_log        — login, entry changes, master resets
```

---

## Deployment

### Supabase (Recommended for PostgreSQL)
1. Create a Supabase project at supabase.com
2. Copy the connection string from Settings → Database
3. Run the migration in Supabase SQL Editor
4. Set `DATABASE_URL` in your backend `.env`

### Railway / Render / Fly.io (Backend)
```bash
# Set environment variables in dashboard, then:
railway up
# or
render deploy
```

### Vercel / Netlify (Frontend)
The frontend is a single HTML file — drop `frontend/src/index.html` into any static host.
Update the `API` constant at the top of the `<script>` to your production backend URL.

### Production Checklist
- [ ] Set `NODE_ENV=production`
- [ ] Use strong random JWT secrets (64+ chars)
- [ ] Configure real SMTP (SendGrid, Postmark, AWS SES)
- [ ] Enable PostgreSQL SSL (`ssl: { rejectUnauthorized: true }`)
- [ ] Set `FRONTEND_URL` to exact production domain (strict CORS)
- [ ] Put backend behind HTTPS (Nginx / Cloudflare)
- [ ] Set up PostgreSQL backups
- [ ] Monitor with PM2 or container health checks

---

## Security Considerations & Limitations

| Topic | Detail |
|-------|--------|
| **Master key** | Derived client-side, held in JS memory only, cleared on lock |
| **XSS risk** | If XSS is possible, master key in memory is exposed — use CSP headers |
| **Recovery key** | Shown once, emailed once — user must store safely |
| **TOTP secret** | Stored in DB — should be encrypted at rest in production |
| **Refresh tokens** | Stored in DB + localStorage; rotate on every use |
| **Audit log** | All sensitive actions logged with IP and timestamp |
| **No server-side search** | name_preview (plaintext label) stored for display only |

---

## Technology Choices

| Need | Choice | Why |
|------|--------|-----|
| Encryption | Web Crypto API (AES-256-GCM) | Native browser, no library trust needed |
| Key derivation | PBKDF2 (310k iterations) | Standardised, widely supported |
| Password hashing | bcrypt (12 rounds) | Industry standard for login passwords |
| OTP | Custom 6-digit + bcrypt | Simple, no 3rd-party dependency |
| TOTP | otpauth library | RFC 6238 compliant, Google Authenticator compatible |
| Email | Nodemailer | Flexible SMTP, works with any provider |
| Auth tokens | JWT (RS256-equivalent via HS256) | Stateless access + DB-tracked refresh |
| DB | PostgreSQL | ACID, UUID, JSONB, strong consistency |
