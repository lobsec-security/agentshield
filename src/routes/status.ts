/**
 * GET /api/status — Health Check & Service Info Route
 */

import { Router, Request, Response } from 'express';
import { threatStore } from '../data/threat-store';
import { SCAM_ADDRESSES } from '../data/scam-addresses';

const router = Router();

const VERSION = '1.0.0';
const START_TIME = new Date().toISOString();

router.get('/', (_req: Request, res: Response) => {
  const stats = threatStore.getStats();
  const uptimeSeconds = Math.floor(stats.uptimeMs / 1000);
  const hours = Math.floor(uptimeSeconds / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);
  const seconds = uptimeSeconds % 60;

  return res.json({
    service: 'AgentShield',
    version: VERSION,
    description: 'Solana Agent Security API — Runtime protection for AI agents',
    status: 'operational',
    uptime: `${hours}h ${minutes}m ${seconds}s`,
    startedAt: START_TIME,
    stats: {
      totalScans: stats.totalScans,
      totalAddressChecks: stats.totalAddressChecks,
      totalTxValidations: stats.totalTxValidations,
      threatsDetected: stats.threatsDetected,
      blockedTransactions: stats.blockedTransactions,
      recentThreats: stats.recentThreats,
      knownScamAddresses: SCAM_ADDRESSES.length,
    },
    endpoints: {
      'POST /api/scan': 'Scan code/plugins for malicious patterns',
      'GET /api/check/:address': 'Check Solana address safety',
      'POST /api/validate-tx': 'Validate transaction before execution',
      'GET /api/threats': 'Threat intelligence feed',
      'GET /api/status': 'This endpoint',
    },
    timestamp: new Date().toISOString(),
  });
});

export default router;
