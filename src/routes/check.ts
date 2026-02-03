/**
 * GET /api/check/:address — Address Safety Check Route
 */

import { Router, Request, Response } from 'express';
import { checkAddress } from '../scanners/address-checker';
import { threatStore } from '../data/threat-store';

const router = Router();

router.get('/:address', async (req: Request, res: Response) => {
  try {
    const address = req.params.address as string;

    if (!address || address.length < 32 || address.length > 44) {
      return res.status(400).json({
        error: 'Invalid Solana address format. Must be 32-44 characters.',
      });
    }

    threatStore.incrementAddressChecks();
    const result = await checkAddress(address);

    // Log if flagged
    if (result.riskScore >= 30) {
      threatStore.addThreat({
        type: 'address_flag',
        severity: result.riskScore >= 70 ? 'critical' : result.riskScore >= 40 ? 'high' : 'medium',
        title: `Flagged address: ${address.substring(0, 8)}...`,
        description: `Risk score ${result.riskScore}/100. Flags: ${result.flags.join(', ')}`,
        metadata: {
          address,
          riskScore: result.riskScore,
          flags: result.flags,
          scamMatch: result.scamMatch?.category || null,
        },
      });
    }

    return res.json(result);
  } catch (error: any) {
    console.error('Address check error:', error);
    return res.status(500).json({ error: 'Internal address check error' });
  }
});

export default router;
