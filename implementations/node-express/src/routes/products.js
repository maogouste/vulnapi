/**
 * Products routes with SQL Injection vulnerability
 *
 * VULNERABILITY V06: SQL Injection in search
 */

import { Router } from 'express';
import { db } from '../database.js';
import { requireAdmin } from '../middleware/auth.js';
import { searchProductsVulnerable } from '../middleware/injection.js';

const router = Router();

/**
 * GET /api/products
 * List products with optional search
 *
 * VULNERABILITY V06 (SQL Injection): Search parameter is not sanitized
 *
 * Exploit examples:
 * - /api/products?search=' OR '1'='1
 * - /api/products?search=' UNION SELECT * FROM users--
 */
router.get('/products', (req, res) => {
  const { search } = req.query;

  if (search) {
    // VULNERABILITY: Using vulnerable search function
    const products = searchProductsVulnerable(search);
    return res.json(products);
  }

  // Normal query when no search
  const products = db.prepare('SELECT * FROM products WHERE is_active = 1').all();
  res.json(products);
});

/**
 * GET /api/products/:id
 * Get product by ID
 *
 * VULNERABILITY V03: Exposes internal_notes and supplier_cost
 */
router.get('/products/:id', (req, res) => {
  const { id } = req.params;

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);

  if (!product) {
    return res.status(404).json({ detail: 'Product not found' });
  }

  res.json(product);
});

/**
 * POST /api/products
 * Create a new product (admin only)
 */
router.post('/products', requireAdmin, (req, res) => {
  const { name, description, price, stock, category, internal_notes, supplier_cost } = req.body;

  if (!name || price === undefined) {
    return res.status(400).json({ detail: 'Name and price are required' });
  }

  const result = db.prepare(`
    INSERT INTO products (name, description, price, stock, category, internal_notes, supplier_cost)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(name, description || null, price, stock || 0, category || null, internal_notes || null, supplier_cost || null);

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(product);
});

/**
 * PUT /api/products/:id
 * Update a product (admin only)
 */
router.put('/products/:id', requireAdmin, (req, res) => {
  const { id } = req.params;

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);

  if (!product) {
    return res.status(404).json({ detail: 'Product not found' });
  }

  const updateFields = [];
  const updateValues = [];
  const allowedFields = ['name', 'description', 'price', 'stock', 'category', 'is_active', 'internal_notes', 'supplier_cost'];

  for (const [field, value] of Object.entries(req.body)) {
    if (allowedFields.includes(field)) {
      updateFields.push(`${field} = ?`);
      updateValues.push(value);
    }
  }

  if (updateFields.length === 0) {
    return res.json(product);
  }

  updateValues.push(id);
  db.prepare(`UPDATE products SET ${updateFields.join(', ')} WHERE id = ?`).run(...updateValues);

  const updatedProduct = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  res.json(updatedProduct);
});

/**
 * DELETE /api/products/:id
 * Delete a product (admin only)
 */
router.delete('/products/:id', requireAdmin, (req, res) => {
  const { id } = req.params;

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);

  if (!product) {
    return res.status(404).json({ detail: 'Product not found' });
  }

  db.prepare('DELETE FROM products WHERE id = ?').run(id);

  res.json({ message: 'Product deleted', product_id: parseInt(id) });
});

export default router;
