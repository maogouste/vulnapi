/**
 * Tools routes with Command Injection vulnerability
 *
 * VULNERABILITY V07: Command Injection
 * VULNERABILITY V08: Security Misconfiguration (debug endpoint)
 * VULNERABILITY V10: Insufficient Logging
 */

import { Router } from 'express';
import os from 'os';
import { requireAuth } from '../middleware/auth.js';
import { pingHostVulnerable, dnsLookupVulnerable } from '../middleware/injection.js';

const router = Router();

/**
 * POST /api/tools/ping
 * Ping a host
 *
 * VULNERABILITY V07 (Command Injection): Host is passed directly to shell
 *
 * Exploit examples:
 * - {"host": "127.0.0.1; cat /etc/passwd"}
 * - {"host": "127.0.0.1 && whoami"}
 * - {"host": "127.0.0.1; ls -la /"}
 * - {"host": "$(cat /etc/passwd)"}
 */
router.post('/tools/ping', requireAuth, (req, res) => {
  const { host } = req.body;

  if (!host) {
    return res.status(400).json({ detail: 'Host is required' });
  }

  const result = pingHostVulnerable(host);

  // VULNERABILITY V10: No logging of potentially malicious activity
  res.json(result);
});

/**
 * POST /api/tools/dns
 * DNS lookup
 *
 * VULNERABILITY V07: Another command injection vector
 *
 * Exploit examples:
 * - {"domain": "google.com; id"}
 * - {"domain": "google.com && cat /etc/shadow"}
 */
router.post('/tools/dns', requireAuth, (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ detail: 'Domain is required' });
  }

  const result = dnsLookupVulnerable(domain);
  res.json(result);
});

/**
 * GET /api/tools/debug
 * Debug endpoint
 *
 * VULNERABILITY V08: Exposes sensitive debug information
 * Should be disabled in production
 */
router.get('/tools/debug', (req, res) => {
  res.json({
    node_version: process.version,
    platform: process.platform,
    arch: process.arch,
    cwd: process.cwd(),
    env_vars: process.env,  // VULNERABILITY: Exposing all env vars!
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    hostname: os.hostname(),
    user_info: os.userInfo(),
  });
});

/**
 * GET /api/tools/headers
 * Show security headers info
 *
 * This endpoint helps demonstrate V08 (Security Misconfiguration)
 */
router.get('/tools/headers', (req, res) => {
  res.json({
    message: 'Check the response headers',
    expected_headers: [
      'X-Content-Type-Options: nosniff',
      'X-Frame-Options: DENY',
      'X-XSS-Protection: 1; mode=block',
      'Strict-Transport-Security: max-age=31536000',
      'Content-Security-Policy: default-src \'self\'',
    ],
    note: 'These headers are NOT set (vulnerability V08)'
  });
});

export default router;
