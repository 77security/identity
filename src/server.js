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
const pinoHttp = require('pino-http')({ 
  logger,
  // This skips logging for health and ready checks
  autoLogging: {
    ignore: (req) => ['/health', '/ready'].includes(req.url)
  }
});

const app = express();
const corsOptions = {
  origin: /https?:\/\/(([^/]+\.)?77security\.com)$/i,
  credentials: true
};
app.use(cors(corsOptions));

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
  host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true' ? true : false, 
  auth: {
    user: process.env.SMTP_USER || 'a47896001@smtp-brevo.com',
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

      const verifyUrl = `https://www.77security.com/?token=${verificationToken}`;
      
      await transporter.sendMail({
        from: `"77 Security" <77security@77security.com>`,
        to: email,
        subject: "Verify your 77 Security account",
        // Text fallback is crucial for deliverability
        text: `Welcome to 77 Security. Please verify your account by visiting: ${verifyUrl}`,
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your Account</title>
          </head>
          <body style="margin: 0; padding: 0; background-color: #f4f7f6; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="padding: 40px 0 30px 0;" align="center">
                  <table border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
                    <tr>
                      <td align="center" style="padding: 40px 0 20px 0; background-color: #0a0a0c;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 28px; letter-spacing: -1px;">77<span style="color: #10b981;">SECURITY</span></h1>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding: 40px 40px 30px 40px;">
                        <h2 style="color: #1a1a1a; font-size: 22px; margin-top: 0;">Confirm your email address</h2>
                        <p style="color: #4a4a4a; font-size: 16px; line-height: 24px;">
                          Welcome to the 77 Security network. To complete your registration and begin contributing to the open-source threat intelligence ecosystem, please verify your email.
                        </p>
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px;">
                          <tr>
                            <td align="center">
                              <a href="${verifyUrl}" style="background-color: #10b981; color: #ffffff; padding: 16px 32px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 16px; display: inline-block;">Verify Account</a>
                            </td>
                          </tr>
                        </table>
                        <p style="color: #888888; font-size: 14px; margin-top: 30px; line-height: 20px;">
                          If you did not sign up for a 77 Security account, you can safely ignore this email.
                        </p>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding: 30px; background-color: #fafafa; border-top: 1px solid #eeeeee; text-align: center;">
                        <p style="color: #999999; font-size: 12px; margin: 0;">
                          Radical Transparency in Security<br>
                          Built on <a href="https://github.com/77security" style="color: #10b981; text-decoration: none;">GitHub</a>
                        </p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </body>
          </html>
        `,
        headers: {
          'List-Unsubscribe': `<mailto:${process.env.SMTP_USER}?subject=unsubscribe>`,
          'X-Entity-Ref-ID': crypto.randomBytes(16).toString('hex')
        }
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

// --- 2. EMAIL VERIFICATION ENDPOINT ---
app.get('/api/auth/verify', async (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.status(400).json({ error: "Verification token is required" });
  }

  // Hash the incoming token to match what's in the DB
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    const result = await pool.query(
      `UPDATE users 
       SET is_verified = TRUE, 
           verification_token_hash = NULL 
       WHERE verification_token_hash = $1 
       RETURNING id, email`,
      [tokenHash]
    );

    if (result.rows.length === 0) {
      req.log.warn({ tokenHash }, "Invalid or expired verification token attempt");
      return res.status(400).json({ error: "Invalid or expired verification token" });
    }

    req.log.info({ userId: result.rows[0].id }, "User email verified successfully");
    res.json({ message: "Email verified successfully! You can now log in." });
  } catch (err) {
    req.log.error({ err }, "Verification process failed");
    res.status(500).json({ error: "Internal server error during verification" });
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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => logger.info(`77 Security Identity API running on port ${PORT}`));