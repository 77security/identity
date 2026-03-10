const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');

// --- LOGGING SETUP ---
const logger = require('pino')({
  level: process.env.LOG_LEVEL || 'info',
  // In K8s, we want raw JSON. Locally, use pino-pretty.
  transport: process.env.NODE_ENV !== 'production' ? { target: 'pino-pretty' } : undefined
});
const pinoHttp = require('pino-http')({ logger });

const app = express();

// Use the logger middleware early to track all requests
app.use(pinoHttp);
app.use(express.json());
app.use(cookieParser());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Monitor pool errors
pool.on('error', (err) => logger.error({ err }, 'Unexpected error on idle database client'));

// --- SMTP CONFIGURATION ---
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.larksuite.com',
  port: parseInt(process.env.SMTP_PORT || '465'),
  secure: process.env.SMTP_SECURE === 'false' ? false : true, 
  auth: {
    user: process.env.SMTP_USER || '77security@77security.com',
    pass: process.env.SMTP_PASS 
  }
});

const VALID_INDUSTRY_KEYS = new Set([
  'CRIT_ENERGY', 'CRIT_WATER', 'FIN_BANK', 'FIN_INS', 'GOV_NAT', 
  'GOV_LOC', 'DEF_BASE', 'HEALTH', 'TECH_SW', 'TECH_HW', 
  'TELECOM', 'MANU_CRIT', 'MANU_GEN', 'TRANS_LOG', 'EDU_RES', 
  'RETAIL', 'MEDIA', 'NON_PROF', 'OTHER'
]);

// --- HELPER: Auth Middleware ---
const authenticate = async (req, res, next) => {
  const sessionId = req.cookies.session_id;
  if (!sessionId) {
    req.log.warn("Unauthorized: No session cookie provided");
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const result = await pool.query(
      'SELECT user_id FROM sessions WHERE id = $1 AND expires_at > NOW()',
      [sessionId]
    );

    if (result.rows.length === 0) {
      req.log.warn({ sessionId }, "Session expired or invalid");
      return res.status(401).json({ error: "Session expired or invalid" });
    }

    req.user_id = result.rows[0].user_id;
    // Add userId to all subsequent logs for this request
    req.log = req.log.child({ userId: req.user_id });
    next();
  } catch (err) {
    req.log.error({ err }, "Authentication middleware error");
    res.status(500).json({ error: "Authentication middleware error" });
  }
};

// Health Probes (Keep these quiet unless they fail)
app.get('/health', (req, res) => res.status(200).send('OK'));
app.get('/ready', (req, res) => res.status(200).send('Ready'));

// --- 1. USER REGISTER ---
app.post('/api/auth/register', async (req, res) => {
  const { email, password, region_code, industry_key } = req.body;

  if (!region_code || region_code.length !== 2) {
    return res.status(400).json({ error: "Invalid region_code. Must be ISO 3166-1 alpha-2." });
  }
  if (!VALID_INDUSTRY_KEYS.has(industry_key)) {
    return res.status(400).json({ error: "Invalid industry_key provided." });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationHash = crypto.createHash('sha256').update(verificationToken).digest('hex');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      const userResult = await client.query(
        `INSERT INTO users (email, password_hash, verification_token_hash) 
         VALUES ($1, $2, $3) RETURNING id`,
        [email, passwordHash, verificationHash]
      );
      
      const userId = userResult.rows[0].id;

      await client.query(
        `INSERT INTO profiles (user_id, region_code, industry_key, display_mode) 
         VALUES ($1, $2, $3, $4)`,
        [userId, region_code.toUpperCase(), industry_key, 'anonymous']
      );

      const verifyUrl = `https://identity.77security.com/verify?token=${verificationToken}`;
      
      await transporter.sendMail({
        from: '"77 Security Identity" <77security@77security.com>',
        to: email,
        subject: "Verify your 77 Security account",
        html: `<div>Verify at ${verifyUrl}</div>`
      });

      await client.query('COMMIT');
      req.log.info({ email, userId }, "User successfully registered");
      res.status(201).json({ message: "Registration successful. Please check your email to verify." });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e; 
    } finally {
      client.release();
    }
  } catch (err) {
    // This logs the full stack trace and the context (email)
    req.log.error({ err, email }, "Registration failure");
    res.status(400).json({ error: "Registration failed. Check logs for details." });
  }
});

// --- 3. USER UPDATE PROFILE ---
app.patch('/api/user/profile', authenticate, async (req, res) => {
  const { region_code, industry_key, display_mode } = req.body;

  try {
    await pool.query(
      `UPDATE profiles 
       SET region_code = COALESCE($1, region_code), 
           industry_key = COALESCE($2, industry_key), 
           display_mode = COALESCE($3, display_mode),
           updated_at = CURRENT_TIMESTAMP
       WHERE user_id = $4`,
      [region_code ? region_code.toUpperCase() : null, industry_key, display_mode, req.user_id]
    );
    req.log.info("Profile updated");
    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    req.log.error({ err }, "Profile update failed");
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// --- 6. GET SELF ---
app.get('/api/user/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.email, p.region_code, p.industry_key, i.display_name as industry_name, p.display_mode 
       FROM users u 
       JOIN profiles p ON u.id = p.user_id 
       LEFT JOIN ref_industries i ON p.industry_key = i.industry_key
       WHERE u.id = $1`,
      [req.user_id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    req.log.error({ err }, "Fetch 'me' failed");
    res.status(500).json({ error: "Could not fetch user info" });
  }
});

const corsOptions = {
  origin: /https?:\/\/(([^/]+\.)?77security\.com)$/i,
  credentials: true
};
app.use(cors(corsOptions));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => logger.info(`77 Security Identity API running on port ${PORT}`));