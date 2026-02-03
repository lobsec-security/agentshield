/**
 * Solana Address Safety Checker
 * 
 * Checks addresses against:
 * 1. Local scam database
 * 2. On-chain heuristics (age, tx count, program interactions)
 * 3. Pattern analysis
 */

import { Connection, PublicKey, ParsedAccountData } from '@solana/web3.js';
import { buildScamLookup, ScamEntry } from '../data/scam-addresses';

const SOLANA_RPC = process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com';

let connection: Connection;
function getConnection(): Connection {
  if (!connection) {
    connection = new Connection(SOLANA_RPC, {
      commitment: 'confirmed',
      confirmTransactionInitialTimeout: 30000,
    });
  }
  return connection;
}

const scamLookup = buildScamLookup();

export interface AddressCheckResult {
  address: string;
  safe: boolean;
  riskScore: number;
  flags: string[];
  firstSeen: string | null;
  txCount: number;
  accountAge: string | null;
  balance: number | null;
  isProgram: boolean;
  scamMatch: ScamEntry | null;
  checkedAt: string;
}

export async function checkAddress(address: string): Promise<AddressCheckResult> {
  const flags: string[] = [];
  let riskScore = 0;
  let firstSeen: string | null = null;
  let txCount = 0;
  let balance: number | null = null;
  let accountAge: string | null = null;
  let isProgram = false;

  // Validate address format
  let pubkey: PublicKey;
  try {
    pubkey = new PublicKey(address);
  } catch {
    return {
      address,
      safe: false,
      riskScore: 100,
      flags: ['INVALID_ADDRESS'],
      firstSeen: null,
      txCount: 0,
      accountAge: null,
      balance: null,
      isProgram: false,
      scamMatch: null,
      checkedAt: new Date().toISOString(),
    };
  }

  // ── Check Local Scam Database ──
  const scamMatch = scamLookup.get(address) || null;
  if (scamMatch) {
    flags.push(`KNOWN_SCAM: ${scamMatch.category}`);
    flags.push(`SCAM_DESCRIPTION: ${scamMatch.description}`);

    const severityScores: Record<string, number> = {
      critical: 50,
      high: 35,
      medium: 20,
      low: 10,
    };
    riskScore += severityScores[scamMatch.severity] || 25;
  }

  // ── On-Chain Checks ──
  try {
    const conn = getConnection();

    // Get account info
    const accountInfo = await conn.getAccountInfo(pubkey);

    if (!accountInfo) {
      flags.push('ACCOUNT_NOT_FOUND');
      riskScore += 15;
    } else {
      balance = accountInfo.lamports / 1e9; // Convert to SOL
      isProgram = accountInfo.executable;

      if (isProgram) {
        flags.push('IS_PROGRAM');
        // Programs are less likely to be scams (but could be malicious programs)
      }

      // Very new account with high balance could be suspicious
      if (balance > 100) {
        flags.push('HIGH_BALANCE');
      }
    }

    // Get transaction signatures (limited)
    try {
      const signatures = await conn.getSignaturesForAddress(pubkey, { limit: 100 });
      txCount = signatures.length;

      if (signatures.length > 0) {
        const oldest = signatures[signatures.length - 1];
        if (oldest.blockTime) {
          const date = new Date(oldest.blockTime * 1000);
          firstSeen = date.toISOString();

          // Calculate account age
          const ageMs = Date.now() - date.getTime();
          const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
          accountAge = `${ageDays} days`;

          // New accounts are riskier
          if (ageDays < 1) {
            flags.push('VERY_NEW_ACCOUNT');
            riskScore += 20;
          } else if (ageDays < 7) {
            flags.push('NEW_ACCOUNT');
            riskScore += 10;
          } else if (ageDays < 30) {
            flags.push('RECENT_ACCOUNT');
            riskScore += 5;
          }
        }
      }

      // Suspicious patterns
      if (txCount === 0) {
        flags.push('NO_TRANSACTION_HISTORY');
        riskScore += 10;
      } else if (txCount === 100) {
        // We hit the limit, account is active
        flags.push('HIGH_ACTIVITY');
      }

      // Check for rapid transactions (many in short time)
      if (signatures.length >= 50) {
        const first = signatures[0].blockTime || 0;
        const last = signatures[Math.min(49, signatures.length - 1)].blockTime || 0;
        if (first && last) {
          const timeSpan = first - last;
          if (timeSpan < 3600) { // 50+ txs in under an hour
            flags.push('RAPID_TRANSACTIONS');
            riskScore += 15;
          }
        }
      }
    } catch (sigError: any) {
      // Rate limited or other error — don't penalize
      flags.push('TX_HISTORY_UNAVAILABLE');
    }
  } catch (rpcError: any) {
    flags.push('RPC_ERROR');
    // Don't make judgment without data
  }

  // Cap risk score
  const finalScore = Math.min(100, Math.max(0, riskScore));

  return {
    address,
    safe: finalScore < 30 && !scamMatch,
    riskScore: finalScore,
    flags,
    firstSeen,
    txCount,
    accountAge,
    balance,
    isProgram,
    scamMatch,
    checkedAt: new Date().toISOString(),
  };
}
