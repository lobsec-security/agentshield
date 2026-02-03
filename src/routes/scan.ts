/**
 * POST /api/scan — Code/Plugin Scanner Route
 */

import { Router, Request, Response } from 'express';
import { scanCode } from '../scanners/code-scanner';
import { threatStore } from '../data/threat-store';
import { writeThreatToChain } from '../solana/threat-registry';
import fetch from 'node-fetch';
import * as crypto from 'crypto';

const router = Router();

router.post('/', async (req: Request, res: Response) => {
  try {
    const { url, code } = req.body;

    if (!url && !code) {
      return res.status(400).json({
        error: 'Either "url" or "code" must be provided',
        example: { url: 'https://example.com/plugin.js' },
        example2: { code: 'const x = eval("malicious")' },
      });
    }

    let sourceCode: string;
    let source: string;

    if (code) {
      // Direct code submission
      if (typeof code !== 'string') {
        return res.status(400).json({ error: '"code" must be a string' });
      }
      if (code.length > 1_000_000) {
        return res.status(400).json({ error: 'Code too large (max 1MB)' });
      }
      sourceCode = code;
      source = 'direct';
    } else {
      // URL fetch
      if (typeof url !== 'string') {
        return res.status(400).json({ error: '"url" must be a string' });
      }

      // Validate URL
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(url);
      } catch {
        return res.status(400).json({ error: 'Invalid URL format' });
      }

      // Block internal/private URLs
      const hostname = parsedUrl.hostname.toLowerCase();
      if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('10.') ||
        hostname.startsWith('172.') ||
        hostname === '0.0.0.0'
      ) {
        return res.status(400).json({ error: 'Cannot scan internal/private URLs' });
      }

      try {
        const response = await fetch(url, {
          timeout: 10000,
          size: 1_000_000, // 1MB max
          headers: {
            'User-Agent': 'AgentShield/1.0 Security Scanner',
          },
        });

        if (!response.ok) {
          return res.status(400).json({
            error: `Failed to fetch URL: HTTP ${response.status}`,
          });
        }

        sourceCode = await response.text();
        source = url;
      } catch (fetchError: any) {
        return res.status(400).json({
          error: `Failed to fetch URL: ${fetchError.message}`,
        });
      }
    }

    // Run the scan
    threatStore.incrementScans();
    const result = scanCode(sourceCode);

    // Log threat if dangerous
    if (result.riskScore >= 50) {
      const severity = result.riskScore >= 80 ? 'critical' : result.riskScore >= 50 ? 'high' : 'medium';
      const categories = [...new Set(result.detections.map(d => d.category))];
      
      threatStore.addThreat({
        type: 'scan_detection',
        severity,
        title: `Dangerous code detected (score: ${result.riskScore})`,
        description: result.summary,
        metadata: {
          source,
          riskScore: result.riskScore,
          detectionCount: result.detections.length,
          categories,
        },
      });
      
      // Write critical threats to Solana devnet (async, don't block response)
      if (result.riskScore >= 70) {
        const codeHash = crypto.createHash('sha256').update(sourceCode).digest('hex').slice(0, 8);
        writeThreatToChain({
          type: 'SCAN',
          sev: result.riskScore >= 80 ? 'C' : 'H',
          cat: categories[0] || 'unknown',
          score: result.riskScore,
          hash: codeHash,
          ts: Math.floor(Date.now() / 1000),
        }).catch(() => {}); // Fire and forget
      }
    }

    return res.json(result);
  } catch (error: any) {
    console.error('Scan error:', error);
    return res.status(500).json({ error: 'Internal scan error' });
  }
});

export default router;
