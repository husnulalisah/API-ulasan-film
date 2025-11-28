// Pastikan db.js Anda seperti ini:
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
  // Hapus bagian 'ssl: { rejectUnauthorized: false }'
    // karena sudah di-handle oleh '?sslmode=require' di URL Neon Anda.
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};