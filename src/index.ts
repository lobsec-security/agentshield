/**
 * AgentShield — Solana Agent Security API
 * 
 * Runtime protection for AI agents on Solana.
 * Scans code, validates addresses, blocks malicious transactions.
 * 
 * Port: 3005
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import scanRouter from './routes/scan';
import checkRouter from './routes/check';
import validateTxRouter from './routes/validate-tx';
import threatsRouter from './routes/threats';
import statusRouter from './routes/status';
import scoreRouter from './routes/score';
import { SCAM_ADDRESSES } from './data/scam-addresses';
import { initRegistry, getRegistryStats } from './solana/threat-registry';

const app = express();
const PORT = process.env.PORT || 3005;

// ── Middleware ───────────────────────────────────────────────────────────────

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded. Try again later.' },
});
app.use(globalLimiter);

// Stricter rate limit for scan endpoint (expensive)
const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Scan rate limit exceeded. Max 30 scans per minute.' },
});

// ── Routes ──────────────────────────────────────────────────────────────────

app.use('/api/scan', scanLimiter, scanRouter);
app.use('/api/check', checkRouter);
app.use('/api/validate-tx', validateTxRouter);
app.use('/api/threats', threatsRouter);
app.use('/api/score', scoreRouter);
app.use('/api/status', statusRouter);

// Initialize Solana threat registry
const registry = initRegistry();

// Root redirect to status
app.get('/', (_req, res) => {
  res.redirect('/api/status');
});

// API docs at /api
app.get('/api', (_req, res) => {
  res.json({
    name: 'AgentShield API',
    version: '1.0.0',
    description: 'Solana Agent Security API — Runtime protection for AI agents',
    docs: 'https://github.com/lobsec-security/agentshield',
    endpoints: [
      {
        method: 'POST',
        path: '/api/scan',
        description: 'Scan code or plugins for malicious patterns',
        body: '{ "url": "https://..." } or { "code": "..." }',
        response: '{ "safe": boolean, "riskScore": 0-100, "detections": [...], "summary": "..." }',
      },
      {
        method: 'GET',
        path: '/api/check/:address',
        description: 'Check a Solana address against scam databases and on-chain heuristics',
        response: '{ "address": "...", "safe": boolean, "riskScore": 0-100, "flags": [...] }',
      },
      {
        method: 'POST',
        path: '/api/validate-tx',
        description: 'Validate a transaction before execution',
        body: '{ "destination": "...", "amount": number, "token": "SOL", "context": "..." }',
        response: '{ "safe": boolean, "riskScore": 0-100, "recommendation": "proceed|review|block" }',
      },
      {
        method: 'GET',
        path: '/api/threats',
        description: 'Get recent threat intelligence',
        params: '?since=<ISO timestamp>&limit=<n>',
        response: '{ "threats": [...], "count": number }',
      },
      {
        method: 'POST',
        path: '/api/score',
        description: 'Score an AI agent\'s security posture (0-100, A+ to F grade)',
        body: '{ "name": "...", "codeUrl?": "...", "walletAddress?": "...", "skills?": [...], "description?": "...", "code?": "..." }',
        response: '{ "agent": "...", "overallScore": 0-100, "grade": "A+"-"F", "dimensions": {...}, "flags": [...] }',
      },
      {
        method: 'GET',
        path: '/api/score/leaderboard',
        description: 'Agent security leaderboard (top scored agents)',
      },
      {
        method: 'GET',
        path: '/api/status',
        description: 'Service health check and statistics',
      },
    ],
  });
});

// ── 404 Handler ─────────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({
    error: 'Not found',
    hint: 'Try GET /api for API documentation',
  });
});

// ── Error Handler ───────────────────────────────────────────────────────────

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start Server ────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════════════════╗
  ║           🛡️  AgentShield v1.0.0                         ║
  ║     Solana Agent Security API                            ║
  ╠═══════════════════════════════════════════════════════════╣
  ║  Port:           ${String(PORT).padEnd(39)}║
  ║  Scam DB:        ${String(SCAM_ADDRESSES.length + ' known addresses').padEnd(39)}║
  ║  Environment:    ${String(process.env.NODE_ENV || 'development').padEnd(39)}║
  ╠═══════════════════════════════════════════════════════════╣
  ║  POST /api/scan          Scan code/plugins               ║
  ║  GET  /api/check/:addr   Address safety check            ║
  ║  POST /api/validate-tx   Transaction validation          ║
  ║  GET  /api/threats       Threat intel feed               ║
  ║  GET  /api/status        Health check                    ║
  ║  POST /api/score         Agent security scoring           ║
  ║  GET  /api               API documentation               ║
  ╠═══════════════════════════════════════════════════════════╣
  ║  Solana Registry: ${String(registry.enabled ? '✅ ' + registry.address.slice(0, 20) + '...' : '⚠️  Not funded (devnet)').padEnd(38)}║
  ╚═══════════════════════════════════════════════════════════╝
  `);
});

export default app;
