/**
 * AgentShield Code Scanner
 * 
 * Scans code/plugins for:
 * - Shell execution patterns
 * - Network exfiltration
 * - Wallet/key access
 * - Prompt injection
 * - Obfuscation techniques
 * - Base64 payloads
 * - Hidden instructions
 */

export interface Detection {
  pattern: string;
  category: 'shell_exec' | 'network_exfil' | 'wallet_drain' | 'prompt_injection' | 'obfuscation' | 'base64_payload' | 'hidden_instruction' | 'data_access' | 'crypto_theft';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  line?: number;
  match: string;
  confidence: number; // 0-100
}

export interface ScanResult {
  safe: boolean;
  riskScore: number; // 0-100
  detections: Detection[];
  summary: string;
  scannedAt: string;
  codeLength: number;
  scanDurationMs: number;
}

interface PatternRule {
  regex: RegExp;
  category: Detection['category'];
  severity: Detection['severity'];
  description: string;
  confidence: number;
  weight: number; // contribution to risk score
}

// ── Detection Patterns ──────────────────────────────────────────────────────

const PATTERNS: PatternRule[] = [
  // ── Shell Execution (Critical) ──
  {
    regex: /\brequire\s*\(\s*['"`]child_process['"`]\s*\)/gi,
    category: 'shell_exec',
    severity: 'critical',
    description: 'Imports child_process module — can execute arbitrary system commands',
    confidence: 95,
    weight: 25,
  },
  {
    regex: /\bfrom\s+['"`]child_process['"`]/gi,
    category: 'shell_exec',
    severity: 'critical',
    description: 'ES module import of child_process',
    confidence: 95,
    weight: 25,
  },
  {
    regex: /\b(?:exec|execSync|spawn|spawnSync|fork|execFile|execFileSync)\s*\(/gi,
    category: 'shell_exec',
    severity: 'critical',
    description: 'Direct shell command execution function call',
    confidence: 90,
    weight: 20,
  },
  {
    regex: /child_process\s*\.\s*(?:exec|spawn|fork|execFile)/gi,
    category: 'shell_exec',
    severity: 'critical',
    description: 'child_process method invocation',
    confidence: 95,
    weight: 25,
  },
  {
    regex: /\bprocess\.(?:exit|kill|abort)\s*\(/gi,
    category: 'shell_exec',
    severity: 'high',
    description: 'Process termination — could be used to crash host',
    confidence: 70,
    weight: 10,
  },
  {
    regex: /\brequire\s*\(\s*['"`](?:os|fs|path|net|dgram|cluster|vm|repl)['"`]\s*\)/gi,
    category: 'shell_exec',
    severity: 'medium',
    description: 'Imports sensitive Node.js core module',
    confidence: 60,
    weight: 8,
  },
  {
    regex: /\bshelljs\b|\bexeca\b|\bcross-spawn\b/gi,
    category: 'shell_exec',
    severity: 'high',
    description: 'Third-party shell execution library',
    confidence: 85,
    weight: 15,
  },

  // ── Network Exfiltration (Critical) ──
  {
    regex: /\bfetch\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)/gi,
    category: 'network_exfil',
    severity: 'high',
    description: 'HTTP request to external domain — potential data exfiltration',
    confidence: 60,
    weight: 10,
  },
  {
    regex: /\b(?:axios|got|request|superagent|node-fetch|undici)\b/gi,
    category: 'network_exfil',
    severity: 'medium',
    description: 'HTTP client library — review outbound connections',
    confidence: 40,
    weight: 5,
  },
  {
    regex: /new\s+WebSocket\s*\(/gi,
    category: 'network_exfil',
    severity: 'high',
    description: 'WebSocket connection — could stream data to external server',
    confidence: 70,
    weight: 12,
  },
  {
    regex: /\b(?:dns|net|dgram|tls|https?)\s*\.\s*(?:connect|request|createConnection|lookup)/gi,
    category: 'network_exfil',
    severity: 'high',
    description: 'Low-level network connection — bypasses HTTP monitoring',
    confidence: 80,
    weight: 15,
  },
  {
    regex: /\.(?:send|write|emit)\s*\(.*(?:private|secret|key|mnemonic|seed|password|token)/gi,
    category: 'network_exfil',
    severity: 'critical',
    description: 'Sending sensitive data over network connection',
    confidence: 85,
    weight: 25,
  },
  {
    regex: /webhook[s]?\s*[=:]\s*['"`]https?:\/\//gi,
    category: 'network_exfil',
    severity: 'critical',
    description: 'Webhook URL configured — likely exfiltration endpoint',
    confidence: 80,
    weight: 20,
  },
  {
    regex: /discord(?:app)?\.com\/api\/webhooks\//gi,
    category: 'network_exfil',
    severity: 'critical',
    description: 'Discord webhook — common exfiltration channel for stolen data',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /api\.telegram\.org\/bot/gi,
    category: 'network_exfil',
    severity: 'critical',
    description: 'Telegram bot API — common exfiltration channel',
    confidence: 90,
    weight: 25,
  },

  // ── Wallet/Key Access (Critical) ──
  {
    regex: /\b(?:privateKey|private_key|privKey|priv_key)\b/gi,
    category: 'wallet_drain',
    severity: 'critical',
    description: 'Accesses private key — potential wallet theft',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /\b(?:secretKey|secret_key|keypair|keyPair)\b/gi,
    category: 'wallet_drain',
    severity: 'critical',
    description: 'Accesses secret key or keypair',
    confidence: 85,
    weight: 20,
  },
  {
    regex: /\b(?:mnemonic|seed[Pp]hrase|seed_phrase|recovery[Pp]hrase|recovery_phrase)\b/gi,
    category: 'wallet_drain',
    severity: 'critical',
    description: 'Accesses mnemonic/seed phrase — wallet recovery theft',
    confidence: 95,
    weight: 30,
  },
  {
    regex: /Keypair\s*\.\s*fromSecretKey/gi,
    category: 'wallet_drain',
    severity: 'critical',
    description: 'Reconstructing Solana Keypair from secret key bytes',
    confidence: 95,
    weight: 30,
  },
  {
    regex: /Keypair\s*\.\s*fromSeed/gi,
    category: 'wallet_drain',
    severity: 'critical',
    description: 'Reconstructing Solana Keypair from seed',
    confidence: 95,
    weight: 30,
  },
  {
    regex: /\bbs58\s*\.\s*decode\b/gi,
    category: 'wallet_drain',
    severity: 'high',
    description: 'Base58 decoding — could be decoding wallet keys',
    confidence: 60,
    weight: 10,
  },
  {
    regex: /process\.env\s*\[\s*['"`](?:.*(?:KEY|SECRET|PRIVATE|MNEMONIC|SEED).*?)['"`]\s*\]/gi,
    category: 'wallet_drain',
    severity: 'high',
    description: 'Reading sensitive environment variables (keys/secrets)',
    confidence: 75,
    weight: 15,
  },
  {
    regex: /\.(?:signTransaction|signAllTransactions|signMessage)\s*\(/gi,
    category: 'wallet_drain',
    severity: 'high',
    description: 'Transaction/message signing — verify authorization',
    confidence: 50,
    weight: 8,
  },
  {
    regex: /SystemProgram\s*\.\s*transfer\s*\(/gi,
    category: 'wallet_drain',
    severity: 'high',
    description: 'SOL transfer instruction — verify recipient is authorized',
    confidence: 50,
    weight: 8,
  },
  {
    regex: /\btransfer\s*\(.*(?:lamports|amount).*\)/gi,
    category: 'wallet_drain',
    severity: 'medium',
    description: 'Token/SOL transfer with amount — review authorization',
    confidence: 40,
    weight: 6,
  },
  {
    regex: /solana-keygen|solana\s+config\s+set/gi,
    category: 'wallet_drain',
    severity: 'critical',
    description: 'Solana CLI key generation or config modification',
    confidence: 85,
    weight: 20,
  },

  // ── Prompt Injection (Critical) ──
  {
    regex: /\bSYSTEM\s*[:]\s*[Yy]ou\s+are\b/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'System prompt override attempt',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /\b(?:OVERRIDE|OVERWRITE)\s*[:]\s*/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'Instruction override marker detected',
    confidence: 85,
    weight: 20,
  },
  {
    regex: /ignore\s+(?:previous|prior|above|all)\s+(?:instructions?|prompts?|rules?|guidelines?)/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'Prompt injection — attempts to override previous instructions',
    confidence: 95,
    weight: 30,
  },
  {
    regex: /forget\s+(?:everything|all|your)\s+(?:previous|prior|instructions?|rules?)/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'Prompt injection — attempts to clear agent instructions',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /\b(?:disregard|bypass)\s+(?:safety|security|restrictions?|guardrails?|filters?)/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'Attempts to bypass safety guardrails',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /<\s*use_tool\b/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'Tool invocation injection — attempts to make agent call tools',
    confidence: 95,
    weight: 30,
  },
  {
    regex: /<\s*(?:function_call|tool_call|invoke|execute)\b/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'Function/tool call injection attempt',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>|<\|system\|>/gi,
    category: 'prompt_injection',
    severity: 'critical',
    description: 'LLM special token injection — attempts to inject control tokens',
    confidence: 95,
    weight: 30,
  },
  {
    regex: /you\s+(?:are|must|should)\s+now\s+(?:act|behave|respond)\s+as/gi,
    category: 'prompt_injection',
    severity: 'high',
    description: 'Role reassignment attempt — jailbreak pattern',
    confidence: 80,
    weight: 15,
  },
  {
    regex: /\bDAN\s+mode\b|do\s+anything\s+now/gi,
    category: 'prompt_injection',
    severity: 'high',
    description: 'DAN (Do Anything Now) jailbreak pattern',
    confidence: 85,
    weight: 18,
  },

  // ── Obfuscation (High) ──
  {
    regex: /\beval\s*\(/gi,
    category: 'obfuscation',
    severity: 'critical',
    description: 'eval() — executes arbitrary code strings',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /new\s+Function\s*\(/gi,
    category: 'obfuscation',
    severity: 'critical',
    description: 'Function constructor — creates function from string (like eval)',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /\bsetTimeout\s*\(\s*['"`]/gi,
    category: 'obfuscation',
    severity: 'high',
    description: 'setTimeout with string argument — executes as eval',
    confidence: 80,
    weight: 15,
  },
  {
    regex: /\bsetInterval\s*\(\s*['"`]/gi,
    category: 'obfuscation',
    severity: 'high',
    description: 'setInterval with string argument — executes as eval',
    confidence: 80,
    weight: 15,
  },
  {
    regex: /\b(?:atob|btoa)\s*\(\s*['"`][A-Za-z0-9+\/=]{20,}/gi,
    category: 'base64_payload',
    severity: 'high',
    description: 'Base64 encoding/decoding of substantial payload',
    confidence: 75,
    weight: 15,
  },
  {
    regex: /Buffer\s*\.\s*from\s*\(\s*['"`][A-Za-z0-9+\/=]{20,}['"`]\s*,\s*['"`]base64['"`]\)/gi,
    category: 'base64_payload',
    severity: 'high',
    description: 'Buffer.from with base64 — decoding hidden payload',
    confidence: 80,
    weight: 18,
  },
  {
    regex: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/g,
    category: 'obfuscation',
    severity: 'high',
    description: 'Hex-escaped string sequence — obfuscated code',
    confidence: 75,
    weight: 15,
  },
  {
    regex: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}/g,
    category: 'obfuscation',
    severity: 'high',
    description: 'Unicode-escaped string sequence — obfuscated code',
    confidence: 75,
    weight: 15,
  },
  {
    regex: /\['\\x[0-9a-fA-F]+'\]/g,
    category: 'obfuscation',
    severity: 'high',
    description: 'Hex property access — obfuscated member access',
    confidence: 80,
    weight: 15,
  },
  {
    regex: /String\s*\.\s*fromCharCode\s*\(\s*(?:\d+\s*,?\s*){5,}\)/gi,
    category: 'obfuscation',
    severity: 'high',
    description: 'String.fromCharCode with multiple codes — building hidden strings',
    confidence: 80,
    weight: 18,
  },
  {
    regex: /\b_0x[a-f0-9]{4,}\b/gi,
    category: 'obfuscation',
    severity: 'high',
    description: 'JavaScript obfuscator variable naming pattern',
    confidence: 85,
    weight: 15,
  },

  // ── Hidden Instructions ──
  {
    regex: /<!--[\s\S]*?(?:system|override|ignore|secret|hidden)[\s\S]*?-->/gi,
    category: 'hidden_instruction',
    severity: 'high',
    description: 'HTML comment containing suspicious keywords',
    confidence: 70,
    weight: 12,
  },
  {
    regex: /\/\*[\s\S]*?(?:system|override|ignore|secret|hidden|instruction)[\s\S]*?\*\//gi,
    category: 'hidden_instruction',
    severity: 'medium',
    description: 'Code comment containing suspicious keywords',
    confidence: 50,
    weight: 8,
  },
  {
    regex: /\u200B|\u200C|\u200D|\u2060|\uFEFF/g,
    category: 'hidden_instruction',
    severity: 'high',
    description: 'Zero-width characters detected — possible hidden text',
    confidence: 85,
    weight: 18,
  },
  {
    regex: /[\u2800-\u28FF]{3,}/g,
    category: 'hidden_instruction',
    severity: 'high',
    description: 'Braille pattern characters — possible steganographic hiding',
    confidence: 80,
    weight: 15,
  },

  // ── Data Access ──
  {
    regex: /\bfs\s*\.\s*(?:readFile|readFileSync|readdir|readdirSync|createReadStream)\s*\(/gi,
    category: 'data_access',
    severity: 'high',
    description: 'Filesystem read operation — potential data theft',
    confidence: 65,
    weight: 10,
  },
  {
    regex: /\bfs\s*\.\s*(?:writeFile|writeFileSync|appendFile|createWriteStream|unlink|rm)\s*\(/gi,
    category: 'data_access',
    severity: 'high',
    description: 'Filesystem write/delete operation — potential data destruction',
    confidence: 70,
    weight: 12,
  },
  {
    regex: /(?:\/etc\/passwd|\/etc\/shadow|~\/\.ssh|\.env\b|\.bashrc|\.zshrc)/gi,
    category: 'data_access',
    severity: 'critical',
    description: 'Accessing sensitive system files',
    confidence: 90,
    weight: 25,
  },
  {
    regex: /(?:\.solana\/id\.json|\.config\/solana|solana.*config\.yml)/gi,
    category: 'crypto_theft',
    severity: 'critical',
    description: 'Accessing Solana CLI wallet/config files',
    confidence: 95,
    weight: 30,
  },
  {
    regex: /(?:phantom|solflare|backpack|glow)\s*(?:wallet|extension|keystore)/gi,
    category: 'crypto_theft',
    severity: 'critical',
    description: 'Targeting Solana wallet browser extensions',
    confidence: 85,
    weight: 25,
  },
  {
    regex: /(?:chrome|firefox|brave)\s*(?:extension|profile|data)\s*(?:dir|path|folder)/gi,
    category: 'crypto_theft',
    severity: 'high',
    description: 'Accessing browser extension data — potential wallet theft',
    confidence: 75,
    weight: 15,
  },
];

// ── Scanner Implementation ──────────────────────────────────────────────────

export function scanCode(code: string): ScanResult {
  const startTime = Date.now();
  const detections: Detection[] = [];
  const lines = code.split('\n');

  for (const rule of PATTERNS) {
    // Reset regex state for global patterns
    rule.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(code)) !== null) {
      // Find line number
      const beforeMatch = code.substring(0, match.index);
      const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;

      // Get matched text (truncated for display)
      const matchText = match[0].length > 100 ? match[0].substring(0, 100) + '...' : match[0];

      detections.push({
        pattern: rule.regex.source.substring(0, 80),
        category: rule.category,
        severity: rule.severity,
        description: rule.description,
        line: lineNumber,
        match: matchText,
        confidence: rule.confidence,
      });

      // Prevent infinite loops on zero-length matches
      if (match[0].length === 0) {
        rule.regex.lastIndex++;
      }
    }
  }

  // ── Calculate Risk Score ──
  let rawScore = 0;
  const seenCategories = new Set<string>();

  for (const detection of detections) {
    const rule = PATTERNS.find(r =>
      r.category === detection.category && r.description === detection.description
    );
    if (rule) {
      // First detection of a category weighs more
      const multiplier = seenCategories.has(detection.category) ? 0.3 : 1.0;
      rawScore += rule.weight * multiplier;
      seenCategories.add(detection.category);
    }
  }

  // Normalize to 0-100
  const riskScore = Math.min(100, Math.round(rawScore));

  // ── Heuristic Boosts ──
  let adjustedScore = riskScore;

  // Boost if multiple critical categories detected
  const criticalCategories = new Set(
    detections.filter(d => d.severity === 'critical').map(d => d.category)
  );
  if (criticalCategories.size >= 3) {
    adjustedScore = Math.min(100, adjustedScore + 15);
  }

  // Boost if code has both network + wallet access
  if (seenCategories.has('network_exfil') && (seenCategories.has('wallet_drain') || seenCategories.has('crypto_theft'))) {
    adjustedScore = Math.min(100, adjustedScore + 20);
  }

  // Boost if code has both shell exec + data access
  if (seenCategories.has('shell_exec') && seenCategories.has('data_access')) {
    adjustedScore = Math.min(100, adjustedScore + 10);
  }

  // Entropy check for heavily obfuscated code
  const entropy = calculateEntropy(code);
  if (entropy > 5.5 && code.length > 500) {
    adjustedScore = Math.min(100, adjustedScore + 10);
  }

  const finalScore = Math.min(100, adjustedScore);

  // ── Generate Summary ──
  const summary = generateSummary(detections, finalScore, seenCategories);

  return {
    safe: finalScore < 30,
    riskScore: finalScore,
    detections: deduplicateDetections(detections),
    summary,
    scannedAt: new Date().toISOString(),
    codeLength: code.length,
    scanDurationMs: Date.now() - startTime,
  };
}

function calculateEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

function deduplicateDetections(detections: Detection[]): Detection[] {
  const seen = new Set<string>();
  return detections.filter(d => {
    const key = `${d.category}:${d.description}:${d.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function generateSummary(
  detections: Detection[],
  riskScore: number,
  categories: Set<string>
): string {
  if (detections.length === 0) {
    return 'No suspicious patterns detected. Code appears safe for agent execution.';
  }

  const parts: string[] = [];

  if (riskScore >= 80) {
    parts.push('⛔ CRITICAL RISK — This code is highly dangerous and should NOT be executed.');
  } else if (riskScore >= 50) {
    parts.push('⚠️ HIGH RISK — This code contains suspicious patterns that require manual review.');
  } else if (riskScore >= 30) {
    parts.push('🟡 MODERATE RISK — Some potentially concerning patterns detected.');
  } else {
    parts.push('🟢 LOW RISK — Minor findings, likely safe with review.');
  }

  const criticalCount = detections.filter(d => d.severity === 'critical').length;
  const highCount = detections.filter(d => d.severity === 'high').length;

  parts.push(
    `Found ${detections.length} detection(s): ${criticalCount} critical, ${highCount} high.`
  );

  const categoryLabels: Record<string, string> = {
    shell_exec: 'shell command execution',
    network_exfil: 'network exfiltration',
    wallet_drain: 'wallet/key access',
    prompt_injection: 'prompt injection',
    obfuscation: 'code obfuscation',
    base64_payload: 'base64 encoded payloads',
    hidden_instruction: 'hidden instructions',
    data_access: 'filesystem access',
    crypto_theft: 'cryptocurrency theft',
  };

  const categoryNames = Array.from(categories)
    .map(c => categoryLabels[c] || c)
    .join(', ');

  parts.push(`Categories: ${categoryNames}.`);

  return parts.join(' ');
}
