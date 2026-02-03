/**
 * POST /api/validate-tx — Transaction Validator Route
 */

import { Router, Request, Response } from 'express';
import { validateTransaction, TxValidationRequest } from '../scanners/tx-validator';
import { threatStore } from '../data/threat-store';

const router = Router();

router.post('/', (req: Request, res: Response) => {
  try {
    const { destination, amount, token, context } = req.body;

    if (!destination) {
      return res.status(400).json({
        error: '"destination" is required',
        example: {
          destination: 'SoMeAdDrEsS...',
          amount: 1.5,
          token: 'SOL',
          context: 'Payment for NFT purchase',
        },
      });
    }

    if (typeof amount !== 'number' || isNaN(amount)) {
      return res.status(400).json({ error: '"amount" must be a valid number' });
    }

    const request: TxValidationRequest = {
      destination,
      amount,
      token: token || 'SOL',
      context: context || '',
    };

    threatStore.incrementTxValidations();
    const result = validateTransaction(request);

    // Log blocked transactions
    if (result.recommendation === 'block') {
      threatStore.incrementBlocked();
      threatStore.addThreat({
        type: 'tx_block',
        severity: 'critical',
        title: `Blocked transaction to ${destination.substring(0, 8)}...`,
        description: result.details,
        metadata: {
          destination,
          amount,
          token: request.token,
          riskScore: result.riskScore,
          flags: result.flags,
        },
      });
    } else if (result.recommendation === 'review') {
      threatStore.addThreat({
        type: 'tx_block',
        severity: 'high',
        title: `Flagged transaction to ${destination.substring(0, 8)}... for review`,
        description: result.details,
        metadata: {
          destination,
          amount,
          token: request.token,
          riskScore: result.riskScore,
          flags: result.flags,
        },
      });
    }

    return res.json(result);
  } catch (error: any) {
    console.error('TX validation error:', error);
    return res.status(500).json({ error: 'Internal validation error' });
  }
});

export default router;
