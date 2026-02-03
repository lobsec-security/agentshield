/**
 * GET /api/threats — Threat Intelligence Feed Route
 */

import { Router, Request, Response } from 'express';
import { threatStore } from '../data/threat-store';

const router = Router();

router.get('/', (req: Request, res: Response) => {
  try {
    const since = req.query.since as string | undefined;
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit as string) || 50));

    const threats = threatStore.getThreats(since, limit);

    return res.json({
      threats,
      count: threats.length,
      limit,
      since: since || null,
      fetchedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    console.error('Threats feed error:', error);
    return res.status(500).json({ error: 'Internal error fetching threats' });
  }
});

export default router;
