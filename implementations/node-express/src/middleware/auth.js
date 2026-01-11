/**
 * Vulnerable authentication middleware
 */

import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { db } from '../database.js';

// VULNERABILITY V02: Weak secret key (easily crackable)
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';
const JWT_EXPIRATION = '24h';

/**
 * Hash a password
 * VULNERABILITY: Low salt rounds (should be 10-12)
 */
export function hashPassword(password) {
  return bcrypt.hashSync(password, 4);
}

/**
 * Verify a password
 */
export function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

/**
 * Create JWT token
 * VULNERABILITY V02:
 * - Weak secret key
 * - Role stored in token (can be modified if secret is cracked)
 */
export function createToken(user) {
  return jwt.sign(
    {
      sub: user.username,
      user_id: user.id,
      role: user.role,  // VULNERABILITY: Role in token
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRATION }
  );
}

/**
 * Decode JWT token
 * VULNERABILITY V02: Accepts 'none' algorithm
 */
export function decodeToken(token) {
  try {
    // VULNERABILITY: Accepting multiple algorithms including 'none'
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256', 'HS384', 'HS512', 'none']
    });
    return payload;
  } catch (error) {
    return null;
  }
}

/**
 * Optional authentication middleware
 * Returns user if token valid, null otherwise
 * VULNERABILITY: Allows anonymous access to some endpoints
 */
export function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    return next();
  }

  const token = authHeader.split(' ')[1];
  const payload = decodeToken(token);

  if (!payload) {
    req.user = null;
    return next();
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.user_id);
  req.user = user || null;
  next();
}

/**
 * Required authentication middleware
 * Returns 401 if not authenticated
 */
export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      detail: 'Not authenticated',
      headers: { 'WWW-Authenticate': 'Bearer' }
    });
  }

  const token = authHeader.split(' ')[1];
  const payload = decodeToken(token);

  if (!payload) {
    return res.status(401).json({
      detail: 'Could not validate credentials',
      headers: { 'WWW-Authenticate': 'Bearer' }
    });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.user_id);

  if (!user) {
    return res.status(401).json({
      detail: 'User not found',
      headers: { 'WWW-Authenticate': 'Bearer' }
    });
  }

  req.user = user;
  next();
}

/**
 * Admin authentication middleware
 * VULNERABILITY: Only checks role string (can be bypassed with mass assignment)
 */
export function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user) return; // Already handled by requireAuth

    if (!['admin', 'superadmin'].includes(req.user.role)) {
      return res.status(403).json({ detail: 'Admin access required' });
    }
    next();
  });
}
