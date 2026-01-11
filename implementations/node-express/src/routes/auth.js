/**
 * Authentication routes
 *
 * VULNERABILITIES:
 * - V02: Weak JWT implementation
 * - V04: No rate limiting
 */

import { Router } from 'express';
import { db } from '../database.js';
import {
  hashPassword,
  verifyPassword,
  createToken,
  requireAuth
} from '../middleware/auth.js';

const router = Router();

/**
 * POST /api/register
 * Register a new user
 *
 * VULNERABILITIES:
 * - No password strength validation
 * - No email verification
 * - Returns full user object with sensitive data
 */
router.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ detail: 'Username, email, and password are required' });
  }

  // Check if username exists
  const existingUsername = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existingUsername) {
    return res.status(400).json({ detail: 'Username already registered' });
  }

  // Check if email exists
  const existingEmail = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existingEmail) {
    return res.status(400).json({ detail: 'Email already registered' });
  }

  // VULNERABILITY: No password strength validation
  const passwordHash = hashPassword(password);

  const result = db.prepare(`
    INSERT INTO users (username, email, password_hash, role)
    VALUES (?, ?, ?, 'user')
  `).run(username, email, passwordHash);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);

  // VULNERABILITY: Returns full user object
  res.status(201).json(user);
});

/**
 * POST /api/login
 * Login and get access token
 *
 * VULNERABILITIES:
 * - V04: No rate limiting
 * - V02: Weak JWT implementation
 * - Detailed error messages (user enumeration)
 */
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ detail: 'Username and password are required' });
  }

  // VULNERABILITY: Different error messages allow user enumeration
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    // VULNERABILITY: Reveals that username doesn't exist
    return res.status(401).json({
      detail: 'User not found',
      headers: { 'WWW-Authenticate': 'Bearer' }
    });
  }

  if (!verifyPassword(password, user.password_hash)) {
    // VULNERABILITY: Reveals that password is wrong
    return res.status(401).json({
      detail: 'Incorrect password',
      headers: { 'WWW-Authenticate': 'Bearer' }
    });
  }

  if (!user.is_active) {
    return res.status(401).json({ detail: 'User account is disabled' });
  }

  const token = createToken(user);

  // VULNERABILITY: Returning sensitive info
  res.json({
    access_token: token,
    token_type: 'bearer',
    user_id: user.id,
    role: user.role
  });
});

/**
 * GET /api/me
 * Get current user profile
 *
 * VULNERABILITY V03: Returns excessive data (ssn, credit_card, etc.)
 */
router.get('/me', requireAuth, (req, res) => {
  res.json(req.user);
});

/**
 * POST /api/token/refresh
 * Refresh access token
 *
 * VULNERABILITY: No refresh token rotation
 */
router.post('/token/refresh', requireAuth, (req, res) => {
  const token = createToken(req.user);

  res.json({
    access_token: token,
    token_type: 'bearer',
    user_id: req.user.id,
    role: req.user.role
  });
});

export default router;
