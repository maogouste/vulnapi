/**
 * Flags/Challenges routes
 */

import { Router } from 'express';
import { db } from '../database.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

/**
 * GET /api/challenges
 * List all challenges (flags hidden)
 */
router.get('/challenges', (req, res) => {
  const flags = db.prepare('SELECT challenge_id, description FROM flags ORDER BY challenge_id').all();

  const challenges = flags.map(flag => ({
    id: flag.challenge_id,
    description: flag.description,
    category: flag.challenge_id.startsWith('G') ? 'graphql' : 'rest',
    solved: false  // Would track per-user in a real implementation
  }));

  res.json(challenges);
});

/**
 * POST /api/flags/submit
 * Submit a flag for verification
 */
router.post('/flags/submit', requireAuth, (req, res) => {
  const { flag } = req.body;

  if (!flag) {
    return res.status(400).json({ detail: 'Flag is required' });
  }

  const foundFlag = db.prepare('SELECT * FROM flags WHERE flag_value = ?').get(flag);

  if (!foundFlag) {
    return res.json({
      success: false,
      message: 'Invalid flag'
    });
  }

  res.json({
    success: true,
    message: `Congratulations! You solved challenge ${foundFlag.challenge_id}!`,
    challenge_id: foundFlag.challenge_id,
    description: foundFlag.description
  });
});

/**
 * GET /api/flags/:challenge_id
 * Get flag hint (not the actual flag)
 */
router.get('/flags/:challenge_id', (req, res) => {
  const { challenge_id } = req.params;

  const flag = db.prepare('SELECT challenge_id, description FROM flags WHERE challenge_id = ?').get(challenge_id);

  if (!flag) {
    return res.status(404).json({ detail: 'Challenge not found' });
  }

  res.json({
    challenge_id: flag.challenge_id,
    description: flag.description,
    hint: `Look for the VULNAPI{...} flag pattern related to ${flag.description.toLowerCase()}`
  });
});

export default router;
