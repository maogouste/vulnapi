/**
 * Vulnerable injection implementations
 */

import { execSync, exec } from 'child_process';
import { db } from '../database.js';

/**
 * Search products with SQL injection vulnerability
 *
 * VULNERABILITY V06: Direct string concatenation in SQL query
 * Example exploits:
 * - ' OR '1'='1
 * - ' UNION SELECT id, username, email, password_hash, ssn, credit_card, secret_note, role, 1, 1 FROM users --
 */
export function searchProductsVulnerable(searchTerm) {
  // VULNERABLE: String concatenation in SQL
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`;

  try {
    const products = db.prepare(query).all();
    return products;
  } catch (error) {
    // Return error details (also a vulnerability - information disclosure)
    return { error: error.message, query: query };
  }
}

/**
 * Ping a host with command injection vulnerability
 *
 * VULNERABILITY V07: Direct command execution with user input
 * Example exploits:
 * - 127.0.0.1; cat /etc/passwd
 * - 127.0.0.1 && whoami
 * - $(cat /etc/passwd)
 */
export function pingHostVulnerable(host) {
  // VULNERABLE: Direct command execution with user input
  const command = `ping -c 1 ${host}`;

  try {
    const result = execSync(command, {
      timeout: 10000,
      encoding: 'utf-8',
      shell: true  // VULNERABLE: shell=true with user input
    });

    return {
      success: true,
      command: command,  // VULNERABILITY: Exposing executed command
      stdout: result,
      stderr: ''
    };
  } catch (error) {
    return {
      success: false,
      command: command,
      stdout: error.stdout || '',
      stderr: error.stderr || error.message
    };
  }
}

/**
 * DNS lookup with command injection vulnerability
 *
 * VULNERABILITY V07: Another command injection vector
 * Example exploits:
 * - google.com; id
 * - google.com && cat /etc/shadow
 */
export function dnsLookupVulnerable(domain) {
  const command = `nslookup ${domain}`;

  try {
    const result = execSync(command, {
      timeout: 10000,
      encoding: 'utf-8',
      shell: true
    });

    return {
      success: true,
      domain: domain,
      output: result
    };
  } catch (error) {
    return {
      success: false,
      domain: domain,
      error: error.message
    };
  }
}
