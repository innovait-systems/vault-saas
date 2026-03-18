require('dotenv').config();
const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const routes     = require('./routes');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── SECURITY HEADERS ──────────────────────────────────
app.use(helmet());
app.set('trust proxy', 1);

// ── CORS ──────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// ── RATE LIMITING ─────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  max:      parseInt(process.env.RATE_LIMIT_MAX       || '100'),
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Too many requests. Please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many auth attempts. Please wait 15 minutes.' },
});

app.use(globalLimiter);
app.use('/api/auth/login',        authLimiter);
app.use('/api/auth/register',     authLimiter);
app.use('/api/auth/forgot',       authLimiter);
app.use('/api/auth/reset',        authLimiter);

// ── BODY PARSING ──────────────────────────────────────
app.use(express.json({ limit: '2mb' }));

// ── ROUTES ────────────────────────────────────────────
app.use('/api', routes);

// ── HEALTH CHECK ──────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ── 404 ───────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));

// ── ERROR HANDLER ─────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── START ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🔐 Vault API running on port ${PORT}`);
  console.log(`   ENV: ${process.env.NODE_ENV}`);
  console.log(`   DB:  ${process.env.DATABASE_URL?.split('@')[1] || 'not configured'}\n`);
});

module.exports = app;
