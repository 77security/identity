const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Database connection using the environment variable provided by Kubernetes/Docker
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --- HELPER: Auth Middleware ---
const authenticate = async (req, res, next) => {
  const sessionId = req.cookies.session_id;
  if (!sessionId) return res.status(401).json({ error: "Authentication required" });

  try {
    // Look up active session
    const result = await pool.query(
      'SELECT user_id FROM sessions WHERE id = $1 AND expires_at > NOW()',
      [sessionId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Session expired or invalid" });
    }

    req.user_id = result.rows[0].user_id;
    next();
  } catch (err) {
    res.status(500).json({ error: "Authentication middleware error" });
  }
};

// --- 1. USER REGISTER ---
app.post('/api/auth/register', async (req, res) => {
  const { email, password, region_code, industry, captcha_token } = req.body;

  // Verification: Verify captcha_token here (e.g., Cloudflare Turnstile)
  
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
        `INSERT INTO profiles (user_id, region_code, industry, display_mode) 
         VALUES ($1, $2, $3, $4)`,
        [userId, region_code, industry, 'anonymous']
      );

      await client.query('COMMIT');
      
      // LOGIC: Send email with verificationToken via Azure Communication Services
      console.log(`[EMAIL SIMULATION] To: ${email} | Token: ${verificationToken}`);

      res.status(201).json({ message: "Registration successful. Please verify your email." });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (err) {
    res.status(400).json({ error: "Registration failed. Email might already be registered." });
  }
});

// --- 2. USER LOGIN ---
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!user.is_verified) {
      return res.status(403).json({ error: "Please verify your email first" });
    }

    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24H session

    await pool.query(
      'INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)',
      [sessionId, user.id, expiresAt]
    );

    res.cookie('session_id', sessionId, {
      domain: '.77security.com',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      expires: expiresAt
    });

    res.json({ status: "success", message: "Logged in successfully" });
  } catch (err) {
    res.status(500).json({ error: "Login system error" });
  }
});

// --- 3. USER UPDATE PROFILE ---
app.patch('/api/user/profile', authenticate, async (req, res) => {
  const { region_code, industry, display_mode } = req.body;

  try {
    await pool.query(
      `UPDATE profiles 
       SET region_code = COALESCE($1, region_code), 
           industry = COALESCE($2, industry), 
           display_mode = COALESCE($3, display_mode),
           updated_at = CURRENT_TIMESTAMP
       WHERE user_id = $4`,
      [region_code, industry, display_mode, req.user_id]
    );
    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// --- 4. USER FORGET PASSWORD ---
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  // LOGIC: Generate token, hash it, store in DB, send email
  // IMPORTANT: UI must warn user that this will invalidate encrypted third-party keys (Zero-Knowledge)
  res.json({ message: "If an account exists with that email, a reset link has been sent." });
});

// --- 5. EMAIL VERIFICATION ---
app.get('/api/auth/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send("Token required");

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    const result = await pool.query(
      `UPDATE users SET is_verified = TRUE, verification_token_hash = NULL 
       WHERE verification_token_hash = $1 RETURNING id`,
      [tokenHash]
    );

    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid or expired verification token" });
    res.json({ message: "Email verified! You can now log in." });
  } catch (err) {
    res.status(500).json({ error: "Verification processing error" });
  }
});

// --- 6. GET SELF ---
app.get('/api/user/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.email, p.region_code, p.industry, p.display_mode 
       FROM users u JOIN profiles p ON u.id = p.user_id 
       WHERE u.id = $1`,
      [req.user_id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Could not fetch user info" });
  }
});

// --- 7. GENERATE API KEY ---
app.post('/api/keys/generate', authenticate, async (req, res) => {
  const { name, scopes } = req.body;

  try {
    const rawKey = `77s_${crypto.randomBytes(32).toString('hex')}`; 
    const keyPrefix = rawKey.substring(0, 12);
    // BYTEA storage: digest() returns the Buffer directly
    const keyHash = crypto.createHash('sha256').update(rawKey).digest(); 

    await pool.query(
      `INSERT INTO api_keys (user_id, name, key_prefix, key_hash, scopes) 
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user_id, name, keyPrefix, keyHash, JSON.stringify(scopes || { omnisense: ["read"] })]
    );

    res.status(201).json({ 
      message: "API Key generated. Copy it now; it won't be shown again.",
      api_key: rawKey 
    });
  } catch (err) {
    res.status(500).json({ error: "API Key generation failed" });
  }
});

// --- 8. VERIFY API KEY ---
app.get('/api/keys/verify', async (req, res) => {
  const apiKey = req.header('X-API-Key');
  if (!apiKey) return res.status(401).json({ error: "X-API-Key header is missing" });

  try {
    const incomingHash = crypto.createHash('sha256').update(apiKey).digest();
    const result = await pool.query(
      `UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP 
       WHERE key_hash = $1 RETURNING user_id, name, scopes`,
      [incomingHash]
    );

    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid API Key" });
    
    res.json({ 
      valid: true, 
      owner_id: result.rows[0].user_id, 
      scopes: result.rows[0].scopes 
    });
  } catch (err) {
    res.status(500).json({ error: "API Key verification system failure" });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`77 Security Identity API running on port ${PORT}`));
