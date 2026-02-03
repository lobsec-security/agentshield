/**
 * AgentScorer — Scores AI agents on security posture and output quality
 * Based on the V = P × U × T × N × C formula (adapted for automated scoring)
 * 
 * Dimensions:
 * - Security (S): How secure is the agent? (code quality, known vulns, safe practices)
 * - Output (O): How much verifiable work has the agent produced?
 * - Reputation (R): Community signals, endorsements, history
 * - Integration (I): How well integrated into the ecosystem?
 * - Risk (X): Known risk factors, suspicious behavior
 */

export interface AgentProfile {
  name: string;
  codeUrl?: string;        // GitHub repo URL
  walletAddress?: string;  // Solana wallet
  skills?: string[];       // List of skill/plugin names
  description?: string;
}

export interface AgentScore {
  agent: string;
  overallScore: number;    // 0-100
  grade: string;           // A+ to F
  dimensions: {
    security: number;      // 0-100
    output: number;        // 0-100
    reputation: number;    // 0-100
    integration: number;   // 0-100
    risk: number;          // 0-100 (inverted: 100 = no risk)
  };
  flags: string[];
  recommendations: string[];
  scoredAt: string;
}

// Risk indicators in agent descriptions/code
const RISK_PATTERNS = [
  { pattern: /guaranteed.*(?:profit|return|gains)/i, flag: 'PROMISES_GUARANTEED_RETURNS', impact: -15 },
  { pattern: /send.*(?:first|now|immediately).*(?:receive|get)/i, flag: 'ADVANCE_FEE_LANGUAGE', impact: -20 },
  { pattern: /(?:admin|root|sudo).*access/i, flag: 'REQUESTS_ELEVATED_ACCESS', impact: -10 },
  { pattern: /(?:private.*key|seed.*phrase|mnemonic)/i, flag: 'REFERENCES_PRIVATE_KEYS', impact: -25 },
  { pattern: /(?:act.*fast|limited.*time|hurry|urgent)/i, flag: 'URGENCY_PRESSURE', impact: -10 },
  { pattern: /(?:trust.*me|not.*scam|legit)/i, flag: 'TRUST_MANIPULATION', impact: -15 },
  { pattern: /eval\s*\(|Function\s*\(|exec\s*\(/i, flag: 'DYNAMIC_CODE_EXECUTION', impact: -20 },
  { pattern: /(?:webhook|exfil|c2|command.*control)/i, flag: 'EXFILTRATION_INDICATORS', impact: -30 },
];

// Positive security indicators
const SECURITY_PATTERNS = [
  { pattern: /(?:rate.*limit|throttl)/i, flag: 'HAS_RATE_LIMITING', impact: 10 },
  { pattern: /(?:input.*valid|sanitiz|escap)/i, flag: 'INPUT_VALIDATION', impact: 10 },
  { pattern: /(?:encrypt|hash|hmac)/i, flag: 'USES_ENCRYPTION', impact: 8 },
  { pattern: /(?:audit|security.*review|pentest)/i, flag: 'SECURITY_AWARE', impact: 5 },
  { pattern: /(?:helmet|cors|csp)/i, flag: 'SECURITY_HEADERS', impact: 8 },
  { pattern: /(?:test|spec|jest|mocha)/i, flag: 'HAS_TESTS', impact: 10 },
  { pattern: /(?:typescript|ts-node)/i, flag: 'TYPED_LANGUAGE', impact: 5 },
  { pattern: /(?:error.*handl|try.*catch|\.catch)/i, flag: 'ERROR_HANDLING', impact: 5 },
];

function gradeFromScore(score: number): string {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 85) return 'A-';
  if (score >= 80) return 'B+';
  if (score >= 75) return 'B';
  if (score >= 70) return 'B-';
  if (score >= 65) return 'C+';
  if (score >= 60) return 'C';
  if (score >= 55) return 'C-';
  if (score >= 50) return 'D+';
  if (score >= 45) return 'D';
  if (score >= 40) return 'D-';
  return 'F';
}

export function scoreAgent(profile: AgentProfile, codeContent?: string): AgentScore {
  const flags: string[] = [];
  const recommendations: string[] = [];
  
  let securityScore = 50; // Start neutral
  let outputScore = 30;   // Start low (prove output)
  let reputationScore = 50;
  let integrationScore = 30;
  let riskScore = 80;     // Start optimistic
  
  const textToAnalyze = [
    profile.description || '',
    codeContent || '',
    (profile.skills || []).join(' '),
  ].join(' ');
  
  // Check for risk patterns
  for (const rp of RISK_PATTERNS) {
    if (rp.pattern.test(textToAnalyze)) {
      flags.push(rp.flag);
      riskScore += rp.impact; // Negative impact
    }
  }
  
  // Check for positive security patterns
  for (const sp of SECURITY_PATTERNS) {
    if (sp.pattern.test(textToAnalyze)) {
      flags.push(sp.flag);
      securityScore += sp.impact;
    }
  }
  
  // Code presence bonus
  if (codeContent) {
    const lines = codeContent.split('\n').length;
    if (lines > 100) outputScore += 15;
    if (lines > 500) outputScore += 15;
    if (lines > 1000) outputScore += 10;
    
    // Check for common security anti-patterns in code
    if (/process\.env/.test(codeContent)) {
      flags.push('USES_ENV_VARS');
      securityScore += 5; // Good practice
    }
    if (/\.env/.test(codeContent) && !/\.gitignore/.test(codeContent)) {
      flags.push('POSSIBLE_ENV_LEAK');
      securityScore -= 10;
      recommendations.push('Ensure .env files are in .gitignore');
    }
    
    // Check code quality indicators
    if (/TODO|FIXME|HACK/i.test(codeContent)) {
      flags.push('HAS_TODO_COMMENTS');
      outputScore -= 5;
    }
    if (/console\.log/.test(codeContent)) {
      flags.push('DEBUG_LOGGING');
      recommendations.push('Remove console.log statements in production');
    }
  }
  
  // GitHub repo bonus
  if (profile.codeUrl) {
    integrationScore += 20;
    if (profile.codeUrl.includes('github.com')) {
      flags.push('PUBLIC_REPO');
      integrationScore += 10;
    }
  }
  
  // Wallet presence
  if (profile.walletAddress) {
    integrationScore += 15;
    flags.push('HAS_WALLET');
  }
  
  // Skills/plugins
  if (profile.skills && profile.skills.length > 0) {
    integrationScore += Math.min(profile.skills.length * 5, 20);
  }
  
  // Description quality
  if (profile.description) {
    if (profile.description.length > 200) outputScore += 10;
    if (profile.description.length > 500) outputScore += 5;
  }
  
  // Clamp all scores to 0-100
  securityScore = Math.max(0, Math.min(100, securityScore));
  outputScore = Math.max(0, Math.min(100, outputScore));
  reputationScore = Math.max(0, Math.min(100, reputationScore));
  integrationScore = Math.max(0, Math.min(100, integrationScore));
  riskScore = Math.max(0, Math.min(100, riskScore));
  
  // Overall = weighted average
  const overall = Math.round(
    securityScore * 0.30 +
    outputScore * 0.20 +
    reputationScore * 0.15 +
    integrationScore * 0.15 +
    riskScore * 0.20
  );
  
  // Generate recommendations
  if (securityScore < 60) recommendations.push('Improve code security practices');
  if (outputScore < 40) recommendations.push('Increase verifiable output (public code, demos)');
  if (integrationScore < 40) recommendations.push('Improve ecosystem integration (wallet, repo, skills)');
  if (riskScore < 60) recommendations.push('Address identified risk flags');
  
  return {
    agent: profile.name,
    overallScore: overall,
    grade: gradeFromScore(overall),
    dimensions: {
      security: securityScore,
      output: outputScore,
      reputation: reputationScore,
      integration: integrationScore,
      risk: riskScore,
    },
    flags,
    recommendations,
    scoredAt: new Date().toISOString(),
  };
}

// Score from just a URL (fetch code and score)
export async function scoreFromUrl(name: string, codeUrl: string): Promise<AgentScore> {
  let codeContent: string | undefined;
  
  try {
    // Try to fetch raw content from GitHub
    const rawUrl = codeUrl
      .replace('github.com', 'raw.githubusercontent.com')
      .replace(/\/blob\//, '/');
    
    const fetch = require('node-fetch');
    const res = await fetch(rawUrl, { timeout: 5000 });
    if (res.ok) {
      codeContent = await res.text();
    }
  } catch (e) {
    // Can't fetch, score without code
  }
  
  return scoreAgent({ name, codeUrl }, codeContent);
}
