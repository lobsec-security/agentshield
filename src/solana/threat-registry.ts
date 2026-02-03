/**
 * On-chain Threat Registry — Writes threat reports to Solana as memo transactions
 * This creates an immutable, verifiable record of detected threats on-chain.
 * 
 * Uses Solana Memo Program to write compact threat summaries.
 * Anyone can read the threat feed by querying transactions for our authority address.
 */

import {
  Connection,
  Keypair,
  Transaction,
  TransactionInstruction,
  PublicKey,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import * as fs from 'fs';
import * as path from 'path';

const MEMO_PROGRAM_ID = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const DEVNET_RPC = 'https://api.devnet.solana.com';

// Compact threat format for memo (max 566 bytes)
interface ThreatMemo {
  type: 'SCAN' | 'ADDR' | 'TX';  // Detection type
  sev: 'C' | 'H' | 'M' | 'L';   // Severity
  cat: string;                     // Category
  score: number;                   // Risk score 0-100
  hash?: string;                   // Content hash (first 8 chars)
  ts: number;                      // Unix timestamp
}

let connection: Connection | null = null;
let authority: Keypair | null = null;
let enabled = false;

export function initRegistry(): { address: string; enabled: boolean } {
  try {
    connection = new Connection(DEVNET_RPC, 'confirmed');
    
    // Try to load wallet from standard location
    const walletPath = path.join(process.env.HOME || '', '.config/solana/wallet.json');
    if (fs.existsSync(walletPath)) {
      const keyData = JSON.parse(fs.readFileSync(walletPath, 'utf8'));
      authority = Keypair.fromSecretKey(Uint8Array.from(keyData));
      enabled = true;
      console.log(`🔗 Solana threat registry initialized: ${authority.publicKey.toBase58()}`);
      return { address: authority.publicKey.toBase58(), enabled: true };
    }
    
    // Generate ephemeral keypair if no wallet found
    authority = Keypair.generate();
    console.log(`⚠️  No wallet found, using ephemeral keypair: ${authority.publicKey.toBase58()}`);
    console.log('   Fund with: solana airdrop 1 --url devnet');
    enabled = false; // Can't write without SOL
    return { address: authority.publicKey.toBase58(), enabled: false };
  } catch (e: any) {
    console.error('Failed to init Solana registry:', e.message);
    return { address: '', enabled: false };
  }
}

export async function writeThreatToChain(threat: ThreatMemo): Promise<string | null> {
  if (!enabled || !connection || !authority) {
    return null; // Silent skip if not enabled
  }
  
  try {
    // Check balance first
    const balance = await connection.getBalance(authority.publicKey);
    if (balance < 5000) {
      console.log('⚠️  Insufficient SOL for on-chain write, skipping');
      return null;
    }
    
    // Compact memo format: AS|type|sev|cat|score|hash|ts
    const memo = `AS|${threat.type}|${threat.sev}|${threat.cat}|${threat.score}|${threat.hash || 'none'}|${threat.ts}`;
    
    const instruction = new TransactionInstruction({
      keys: [{ pubkey: authority.publicKey, isSigner: true, isWritable: false }],
      programId: MEMO_PROGRAM_ID,
      data: Buffer.from(memo, 'utf8'),
    });
    
    const tx = new Transaction().add(instruction);
    const sig = await sendAndConfirmTransaction(connection, tx, [authority]);
    
    console.log(`📝 Threat written to Solana devnet: ${sig}`);
    return sig;
  } catch (e: any) {
    console.error('Failed to write threat to chain:', e.message);
    return null;
  }
}

export async function getRegistryStats(): Promise<{
  address: string;
  enabled: boolean;
  balance: number;
  network: string;
}> {
  if (!connection || !authority) {
    return { address: '', enabled: false, balance: 0, network: 'devnet' };
  }
  
  let balance = 0;
  try {
    balance = await connection.getBalance(authority.publicKey);
  } catch (e) {
    // RPC error, return 0
  }
  
  return {
    address: authority.publicKey.toBase58(),
    enabled,
    balance: balance / LAMPORTS_PER_SOL,
    network: 'devnet',
  };
}

// Parse memo from transaction data
export function parseThreatMemo(memoData: string): ThreatMemo | null {
  try {
    const parts = memoData.split('|');
    if (parts[0] !== 'AS' || parts.length < 7) return null;
    
    return {
      type: parts[1] as 'SCAN' | 'ADDR' | 'TX',
      sev: parts[2] as 'C' | 'H' | 'M' | 'L',
      cat: parts[3],
      score: parseInt(parts[4]),
      hash: parts[5] === 'none' ? undefined : parts[5],
      ts: parseInt(parts[6]),
    };
  } catch {
    return null;
  }
}
