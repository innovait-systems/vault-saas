const { Pool } = require('pg');

const config = {};

if (process.env.DATABASE_URL) {
  config.connectionString = process.env.DATABASE_URL;
} else {
  config.user     = process.env.DB_USER;
  config.password = process.env.DB_PASSWORD;
  config.host     = process.env.DB_HOST;
  config.port     = parseInt(process.env.DB_PORT || '6543');
  config.database = process.env.DB_NAME || 'postgres';
}

if (!config.connectionString && !config.host) {
  console.error('❌ No database configuration found (DATABASE_URL or DB_HOST).');
}

const pool = new Pool({
  ...config,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err);
});

const query = (text, params) => pool.query(text, params);

const getClient = () => pool.connect();

module.exports = { query, getClient, pool };