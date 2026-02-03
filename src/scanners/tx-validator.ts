/**
 * Transaction Validator
 * 
 * Validates Solana transactions before execution:
 * 1. Destination address safety
 * 2. Amount analysis
 * 3. Context-based heuristics
 */

import { buildScamLookup, ScamEntry } from '../data/scam-addresses';
import { PublicKey } from '@solana/web3.js';

const scamLookup = buildScamLookup();

export interface TxValidationRequest {
  destination: string;
  amount: number;
  token: string;
  context?: string;
}

export interface TxValidationResult {
  safe: boolean;
  riskScore: number;
  flags: string[];
  recommendation: 'proceed' | 'review' | 'block';
  details: string;
  validatedAt: string;
}

// High-value thresholds by token
const HIGH_VALUE_THRESHOLDS: Record<string, number> = {
  SOL: 10,
  USDC: 1000,
  USDT: 1000,
  BONK: 100000000,
  JUP: 5000,
  DEFAULT: 1000,
};

// Known safe program addresses
const KNOWN_SAFE_PROGRAMS = new Set([
  '11111111111111111111111111111111',             // System Program
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', // Token Program
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', // Associated Token
  'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4', // Jupiter v6
  'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc',  // Orca Whirlpool
  '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8', // Raydium AMM
  'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',  // Metaplex Token Metadata
  'So1endDq2YkqhipRh3WViPa8hFMqFTiRnTNpGRZpubsc', // Solend (Note: deprecated)
  'MangoeUkGQBJhRjjz3PMMoKTJKPrb8eaWRvRHfgjUdZ',  // Mango v4 (Note: exploited)
]);

// Suspicious context patterns
const SUSPICIOUS_CONTEXT_PATTERNS = [
  { regex: /urgent|immediately|right\s+now|hurry|fast|asap/gi, flag: 'URGENCY_PRESSURE', weight: 10 },
  { regex: /double|triple|multiply|guaranteed\s+return|10x|100x/gi, flag: 'UNREALISTIC_RETURNS', weight: 20 },
  { regex: /limited\s+time|expires?\s+soon|last\s+chance|exclusive/gi, flag: 'SCARCITY_PRESSURE', weight: 10 },
  { regex: /trust\s+me|legit|not\s+a?\s*scam|100%\s+safe/gi, flag: 'TRUST_MANIPULATION', weight: 15 },
  { regex: /admin|moderator|support\s+team|official/gi, flag: 'AUTHORITY_IMPERSONATION', weight: 10 },
  { regex: /send.*(?:first|before)|advance.*(?:fee|payment)/gi, flag: 'ADVANCE_FEE_PATTERN', weight: 25 },
  { regex: /verify.*wallet|connect.*wallet.*(?:here|link)/gi, flag: 'WALLET_PHISHING', weight: 20 },
  { regex: /airdrop.*claim|claim.*(?:reward|token|prize)/gi, flag: 'FAKE_AIRDROP', weight: 15 },
];

export function validateTransaction(req: TxValidationRequest): TxValidationResult {
  const flags: string[] = [];
  let riskScore = 0;

  // ── Validate destination address format ──
  try {
    new PublicKey(req.destination);
  } catch {
    return {
      safe: false,
      riskScore: 100,
      flags: ['INVALID_DESTINATION_ADDRESS'],
      recommendation: 'block',
      details: 'Destination address is not a valid Solana public key.',
      validatedAt: new Date().toISOString(),
    };
  }

  // ── Check scam database ──
  const scamEntry = scamLookup.get(req.destination);
  if (scamEntry) {
    flags.push(`KNOWN_SCAM: ${scamEntry.category}`);
    flags.push(`SCAM_DETAIL: ${scamEntry.description}`);
    riskScore += 80;
  }

  // ── Check if destination is a known safe program ──
  if (KNOWN_SAFE_PROGRAMS.has(req.destination)) {
    flags.push('KNOWN_SAFE_PROGRAM');
    riskScore = Math.max(0, riskScore - 20);
  }

  // ── Amount analysis ──
  const token = (req.token || 'SOL').toUpperCase();
  const threshold = HIGH_VALUE_THRESHOLDS[token] || HIGH_VALUE_THRESHOLDS.DEFAULT;

  if (req.amount > threshold * 10) {
    flags.push('EXTREMELY_HIGH_VALUE');
    riskScore += 25;
  } else if (req.amount > threshold) {
    flags.push('HIGH_VALUE_TRANSACTION');
    riskScore += 10;
  }

  if (req.amount <= 0) {
    flags.push('ZERO_OR_NEGATIVE_AMOUNT');
    riskScore += 5;
  }

  // Suspicious round numbers (common in scams)
  if (req.amount > 1 && req.amount === Math.round(req.amount) && req.amount >= 100) {
    flags.push('ROUND_NUMBER_AMOUNT');
    riskScore += 3;
  }

  // ── Context analysis ──
  if (req.context) {
    for (const pattern of SUSPICIOUS_CONTEXT_PATTERNS) {
      if (pattern.regex.test(req.context)) {
        flags.push(pattern.flag);
        riskScore += pattern.weight;
        // Reset regex
        pattern.regex.lastIndex = 0;
      }
    }
  }

  // ── Self-transfer check ──
  // (Would need source address to check — flag for review if no context)
  if (!req.context || req.context.trim().length < 5) {
    flags.push('NO_CONTEXT_PROVIDED');
    riskScore += 5;
  }

  // ── Cap and determine recommendation ──
  const finalScore = Math.min(100, Math.max(0, riskScore));

  let recommendation: 'proceed' | 'review' | 'block';
  let details: string;

  if (finalScore >= 60 || scamEntry) {
    recommendation = 'block';
    details = scamEntry
      ? `⛔ BLOCKED — Destination is a known ${scamEntry.category} address: ${scamEntry.description}`
      : `⛔ BLOCKED — High risk score (${finalScore}/100). Multiple suspicious flags detected.`;
  } else if (finalScore >= 30) {
    recommendation = 'review';
    details = `⚠️ REVIEW REQUIRED — Moderate risk score (${finalScore}/100). ${flags.length} flag(s) detected. Manual review recommended before proceeding.`;
  } else {
    recommendation = 'proceed';
    details = `✅ Transaction appears safe. Risk score: ${finalScore}/100.`;
  }

  return {
    safe: finalScore < 30,
    riskScore: finalScore,
    flags,
    recommendation,
    details,
    validatedAt: new Date().toISOString(),
  };
}
