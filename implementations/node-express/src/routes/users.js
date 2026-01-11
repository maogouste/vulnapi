/**
 * Users routes with BOLA and Mass Assignment vulnerabilities
 *
 * VULNERABILITIES:
 * - V01: Broken Object Level Authorization (BOLA)
 * - V03: Excessive Data Exposure
 * - V05: Mass Assignment
 * - V09: Legacy API version
 */

import { Router } from 'express';
import { db } from '../database.js';
import { optionalAuth, requireAuth, hashPassword } from '../middleware/auth.js';

const router = Router();
const routerV1 = Router();  // Legacy API version

// ==================== Current API v2 ====================

/**
 * GET /api/users
 * List all users
 *
 * VULNERABILITY V03: Returns all users with sensitive data
 * VULNERABILITY: No pagination (DoS potential)
 */
router.get('/users', optionalAuth, (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  res.json(users);
});

/**
 * GET /api/users/:id
 * Get user by ID
 *
 * VULNERABILITY V01 (BOLA): No authorization check!
 * Any authenticated user can access any other user's data.
 *
 * Exploit: GET /api/users/1 (access admin data)
 */
router.get('/users/:id', optionalAuth, (req, res) => {
  const { id } = req.params;

  // VULNERABILITY: No check if current_user.id == user_id
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);

  if (!user) {
    return res.status(404).json({ detail: 'User not found' });
  }

  res.json(user);
});

/**
 * PUT /api/users/:id
 * Update user
 *
 * VULNERABILITY V01 (BOLA): Can update any user
 * VULNERABILITY V05 (Mass Assignment): Can update role, is_active, etc.
 *
 * Exploit: PUT /api/users/1 with {"role": "admin"}
 */
router.put('/users/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  // VULNERABILITY V01: No authorization check
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);

  if (!user) {
    return res.status(404).json({ detail: 'User not found' });
  }

  // VULNERABILITY V05: Mass assignment - all fields from request are applied
  const updateFields = [];
  const updateValues = [];

  // Process password separately
  const updateData = { ...req.body };
  if (updateData.password) {
    updateData.password_hash = hashPassword(updateData.password);
    delete updateData.password;
  }

  // VULNERABLE: Directly applying all fields including role, is_active
  const allowedFields = ['username', 'email', 'password_hash', 'role', 'is_active', 'ssn', 'credit_card', 'secret_note', 'api_key'];

  for (const [field, value] of Object.entries(updateData)) {
    if (allowedFields.includes(field)) {
      updateFields.push(`${field} = ?`);
      updateValues.push(value);
    }
  }

  if (updateFields.length === 0) {
    return res.json(user);
  }

  updateValues.push(id);
  db.prepare(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`).run(...updateValues);

  const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.json(updatedUser);
});

/**
 * DELETE /api/users/:id
 * Delete user
 *
 * VULNERABILITY V01: No authorization check
 * VULNERABILITY V10: No logging of deletion
 */
router.delete('/users/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);

  if (!user) {
    return res.status(404).json({ detail: 'User not found' });
  }

  // VULNERABILITY: No logging, no audit trail
  db.prepare('DELETE FROM users WHERE id = ?').run(id);

  res.json({ message: 'User deleted', user_id: parseInt(id) });
});

// ==================== LEGACY API v1 (V09) ====================

/**
 * GET /api/v1/users
 * Legacy API: List all users
 *
 * VULNERABILITY V09: Old API version with even more data exposure
 * - No authentication required
 * - Exposes password_hash!
 */
routerV1.get('/users', (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();

  // VULNERABILITY V09: Returns password hash and all sensitive data
  res.json(users);
});

/**
 * GET /api/v1/users/:id
 * Legacy API: Get user by ID
 *
 * VULNERABILITY V09: Exposes password hash and all sensitive data
 * No authentication required!
 */
routerV1.get('/users/:id', (req, res) => {
  const { id } = req.params;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);

  if (!user) {
    return res.status(404).json({ detail: 'User not found' });
  }

  res.json(user);
});

export { router as usersRouter, routerV1 as usersRouterV1 };
