/**
 * Database configuration with SQLite
 */

import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DB_PATH = join(__dirname, '..', 'vulnapi.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Initialize tables
function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      is_active INTEGER DEFAULT 1,
      ssn TEXT,
      credit_card TEXT,
      secret_note TEXT,
      api_key TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      stock INTEGER DEFAULT 0,
      category TEXT,
      is_active INTEGER DEFAULT 1,
      internal_notes TEXT,
      supplier_cost REAL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      total_amount REAL DEFAULT 0,
      shipping_address TEXT,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      unit_price REAL NOT NULL,
      FOREIGN KEY (order_id) REFERENCES orders(id),
      FOREIGN KEY (product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS flags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id TEXT UNIQUE NOT NULL,
      flag_value TEXT NOT NULL,
      description TEXT
    );
  `);
}

// Seed database with initial data
function seedDatabase() {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count > 0) {
    return; // Already seeded
  }

  console.log('[*] Seeding database...');

  // Create users
  const insertUser = db.prepare(`
    INSERT INTO users (username, email, password_hash, role, ssn, credit_card, secret_note, api_key)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // VULNERABILITY: Weak password hashing (low salt rounds)
  const hashPassword = (password) => bcrypt.hashSync(password, 4);

  const users = [
    ['admin', 'admin@vulnapi.local', hashPassword('admin123'), 'admin', '123-45-6789', '4111-1111-1111-1111', 'VULNAPI{bola_user_data_exposed}', 'admin-api-key-12345'],
    ['john', 'john@example.com', hashPassword('password123'), 'user', '987-65-4321', '5500-0000-0000-0004', "John's private notes", null],
    ['jane', 'jane@example.com', hashPassword('jane2024'), 'user', '456-78-9012', '3400-0000-0000-009', "Jane's secret data", null],
    ['bob', 'bob@example.com', hashPassword('bob'), 'user', null, null, null, null],
    ['service_account', 'service@vulnapi.local', hashPassword('svc_password_2024'), 'superadmin', null, null, 'Service account - do not delete', 'VULNAPI{jwt_weak_secret_cracked}'],
  ];

  for (const user of users) {
    insertUser.run(...user);
  }

  // Create products
  const insertProduct = db.prepare(`
    INSERT INTO products (name, description, price, stock, category, is_active, internal_notes, supplier_cost)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const products = [
    ['Laptop Pro X1', 'High-performance laptop for professionals', 1299.99, 50, 'Electronics', 1, 'VULNAPI{exposure_internal_data_leak}', 850.00],
    ['Wireless Mouse', 'Ergonomic wireless mouse', 49.99, 200, 'Electronics', 1, 'Supplier: TechCorp, Margin: 60%', 20.00],
    ['USB-C Hub', '7-in-1 USB-C hub with HDMI', 79.99, 150, 'Electronics', 1, 'Best seller Q4 2024', 35.00],
    ['Mechanical Keyboard', 'RGB mechanical keyboard with Cherry MX switches', 149.99, 75, 'Electronics', 1, null, 80.00],
    ['4K Monitor', '27-inch 4K IPS monitor', 399.99, 30, 'Electronics', 1, 'Discontinued model - clearance', 250.00],
    ['Secret Product', 'VULNAPI{sqli_database_dumped}', 9999.99, 1, 'Hidden', 0, 'This product should never be visible', null],
  ];

  for (const product of products) {
    insertProduct.run(...product);
  }

  // Create flags
  const insertFlag = db.prepare(`
    INSERT INTO flags (challenge_id, flag_value, description)
    VALUES (?, ?, ?)
  `);

  const flags = [
    ['V01', 'VULNAPI{bola_user_data_exposed}', 'Found by accessing another user\'s data via BOLA'],
    ['V02', 'VULNAPI{jwt_weak_secret_cracked}', 'Found by cracking the weak JWT secret'],
    ['V03', 'VULNAPI{exposure_internal_data_leak}', 'Found in excessive data exposure in API responses'],
    ['V04', 'VULNAPI{ratelimit_bruteforce_success}', 'Demonstrated by brute forcing login without rate limiting'],
    ['V05', 'VULNAPI{mass_assignment_privilege_escalation}', 'Found by escalating privileges via mass assignment'],
    ['V06', 'VULNAPI{sqli_database_dumped}', 'Found by exploiting SQL injection in product search'],
    ['V07', 'VULNAPI{cmd_injection_rce_achieved}', 'Found by achieving RCE via command injection'],
    ['V08', 'VULNAPI{misconfig_cors_headers_missing}', 'Identified by checking security headers and CORS config'],
    ['V09', 'VULNAPI{version_legacy_api_exposed}', 'Found by discovering and exploiting old API version'],
    ['V10', 'VULNAPI{logging_blind_attack_undetected}', 'Demonstrated by performing attacks without logging'],
    ['G01', 'VULNAPI{graphql_introspection_schema_leaked}', 'Found by using GraphQL introspection'],
    ['G02', 'VULNAPI{graphql_depth_resource_exhaustion}', 'Demonstrated by exploiting unlimited query depth'],
    ['G03', 'VULNAPI{graphql_batch_rate_limit_bypass}', 'Found by batching multiple operations'],
    ['G04', 'VULNAPI{graphql_suggestions_field_enumeration}', 'Found by using error messages to enumerate fields'],
    ['G05', 'VULNAPI{graphql_authz_sensitive_data_exposed}', 'Found by accessing sensitive data without authentication'],
  ];

  for (const flag of flags) {
    insertFlag.run(...flag);
  }

  console.log('[*] Database seeded successfully!');
}

export { db, initDatabase, seedDatabase };
