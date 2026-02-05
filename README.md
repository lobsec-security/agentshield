# 🛡️ AgentShield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/lobsec-security/agentshield/releases)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/lobsec-security/agentshield/actions)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)
[![Solana](https://img.shields.io/badge/Solana-web3.js-9945FF.svg)](https://solana.com/)
[![Express](https://img.shields.io/badge/Express-4.x-lightgrey.svg)](https://expressjs.com/)

**Solana Agent Security API** — Runtime protection for AI agents on Solana.

Built for the [Colosseum Agent Hackathon](https://colosseum.com) by LobSec.

AgentShield provides real-time security scanning for AI agent ecosystems. Before your agent executes a plugin, sends a transaction, or interacts with an address — AgentShield checks it first.

## Quick Start

```bash
npm install
npm run dev    # starts on port 3005
```

## API Endpoints

### `POST /api/scan` — Code/Plugin Scanner

Scans code for malicious patterns including shell execution, wallet draining, prompt injection, and obfuscation.

**Request:**
```json
{
  "code": "const cp = require('child_process'); cp.exec('rm -rf /');"
}
```
or
```json
{
  "url": "https://example.com/plugin.js"
}
```

**Response:**
```json
{
  "safe": false,
  "riskScore": 85,
  "detections": [
    {
      "pattern": "require\\s*\\(\\s*['\"`]child_process...",
      "category": "shell_exec",
      "severity": "critical",
      "description": "Imports child_process module — can execute arbitrary system commands",
      "line": 1,
      "match": "require('child_process')",
      "confidence": 95
    }
  ],
  "summary": "⛔ CRITICAL RISK — This code is highly dangerous and should NOT be executed. Found 2 detection(s): 2 critical, 0 high. Categories: shell command execution.",
  "scannedAt": "2025-02-03T15:00:00.000Z",
  "codeLength": 58,
  "scanDurationMs": 2
}
```

**Detection Categories:**
| Category | Description |
|----------|-------------|
| `shell_exec` | Shell/command execution (`exec`, `spawn`, `child_process`) |
| `network_exfil` | Data exfiltration (webhooks, external HTTP, WebSocket) |
| `wallet_drain` | Wallet/key access (`privateKey`, `mnemonic`, `Keypair`) |
| `prompt_injection` | LLM prompt injection (`ignore previous`, `SYSTEM`, `<use_tool`) |
| `obfuscation` | Code obfuscation (`eval`, `Function`, hex encoding) |
| `base64_payload` | Hidden base64-encoded payloads |
| `hidden_instruction` | Zero-width chars, hidden comments |
| `data_access` | Filesystem read/write operations |
| `crypto_theft` | Targeting wallet files/extensions |

---

### `GET /api/check/:address` — Address Safety Check

Checks a Solana address against known scam databases and on-chain heuristics.

**Request:**
```
GET /api/check/Htp9MGP8Tig923ZFY7Qf2zzbMUmYneFRAhSp7vSg4wxV
```

**Response:**
```json
{
  "address": "Htp9MGP8Tig923ZFY7Qf2zzbMUmYneFRAhSp7vSg4wxV",
  "safe": false,
  "riskScore": 75,
  "flags": ["KNOWN_SCAM: exploit", "SCAM_DESCRIPTION: Mango Markets exploiter"],
  "firstSeen": "2022-10-11T00:00:00.000Z",
  "txCount": 100,
  "accountAge": "850 days",
  "balance": 0.5,
  "isProgram": false,
  "scamMatch": {
    "address": "Htp9MGP8Tig923ZFY7Qf2zzbMUmYneFRAhSp7vSg4wxV",
    "category": "exploit",
    "description": "Mango Markets exploiter — $114M exploit October 2022",
    "severity": "critical"
  },
  "checkedAt": "2025-02-03T15:00:00.000Z"
}
```

**On-chain checks:**
- Account existence and balance
- Transaction history count
- Account age (first seen)
- Program detection
- Rapid transaction pattern detection

---

### `POST /api/validate-tx` — Transaction Validator

Validates a transaction before execution. Checks destination, amount, and context.

**Request:**
```json
{
  "destination": "SomeAddress...",
  "amount": 10,
  "token": "SOL",
  "context": "Payment for NFT mint"
}
```

**Response:**
```json
{
  "safe": true,
  "riskScore": 15,
  "flags": ["HIGH_VALUE_TRANSACTION"],
  "recommendation": "proceed",
  "details": "✅ Transaction appears safe. Risk score: 15/100.",
  "validatedAt": "2025-02-03T15:00:00.000Z"
}
```

**Recommendations:**
| Value | Meaning |
|-------|---------|
| `proceed` | Safe to execute (score < 30) |
| `review` | Needs human review (score 30-59) |
| `block` | Do not execute (score ≥ 60 or known scam) |

**Context Analysis Detects:**
- Urgency pressure ("send immediately", "hurry")
- Unrealistic returns ("guaranteed 100x", "double your SOL")
- Scarcity pressure ("limited time", "last chance")
- Trust manipulation ("trust me", "not a scam")
- Authority impersonation ("admin", "support team")
- Advance fee patterns ("send first to receive")
- Fake airdrops ("claim your reward")
- Wallet phishing ("verify your wallet")

---

### `GET /api/threats` — Threat Intel Feed

Returns recent detected threats.

**Params:**
- `since` — ISO timestamp to filter from (optional)
- `limit` — Max results, 1-200 (default: 50)

**Request:**
```
GET /api/threats?limit=10&since=2025-02-03T00:00:00Z
```

**Response:**
```json
{
  "threats": [
    {
      "id": "thr_abc123_xyz789",
      "type": "scan_detection",
      "severity": "critical",
      "title": "Dangerous code detected (score: 92)",
      "description": "⛔ CRITICAL RISK — ...",
      "metadata": { "source": "direct", "riskScore": 92 },
      "timestamp": "2025-02-03T15:00:00.000Z"
    }
  ],
  "count": 1,
  "limit": 10,
  "since": "2025-02-03T00:00:00Z",
  "fetchedAt": "2025-02-03T15:00:30.000Z"
}
```

---

### `GET /api/status` — Health Check

Returns service info, version, and operational statistics.

```json
{
  "service": "AgentShield",
  "version": "1.0.0",
  "status": "operational",
  "uptime": "2h 15m 30s",
  "stats": {
    "totalScans": 142,
    "totalAddressChecks": 89,
    "totalTxValidations": 56,
    "threatsDetected": 23,
    "blockedTransactions": 7,
    "knownScamAddresses": 20
  }
}
```

---

## Integration Examples

### JavaScript/TypeScript Agent

```typescript
// Before executing a plugin
const scanResult = await fetch('http://localhost:3005/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code: pluginSource }),
}).then(r => r.json());

if (!scanResult.safe) {
  console.error('Plugin blocked:', scanResult.summary);
  return;
}

// Before sending a transaction
const txCheck = await fetch('http://localhost:3005/api/validate-tx', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    destination: recipientAddress,
    amount: 5,
    token: 'SOL',
    context: userMessage,
  }),
}).then(r => r.json());

if (txCheck.recommendation === 'block') {
  console.error('Transaction blocked:', txCheck.details);
  return;
}
```

### Python Agent

```python
import requests

# Scan code
result = requests.post('http://localhost:3005/api/scan', json={
    'code': plugin_source_code
}).json()

if not result['safe']:
    raise SecurityError(result['summary'])

# Check address
check = requests.get(f'http://localhost:3005/api/check/{address}').json()
if not check['safe']:
    raise SecurityError(f"Unsafe address: {check['flags']}")
```

## Architecture

```
agentshield/
├── src/
│   ├── index.ts              # Express server entry point
│   ├── scanners/
│   │   ├── code-scanner.ts   # Pattern-based code analysis (60+ rules)
│   │   ├── address-checker.ts # Solana address verification
│   │   └── tx-validator.ts   # Transaction pre-flight checks
│   ├── routes/
│   │   ├── scan.ts           # POST /api/scan
│   │   ├── check.ts          # GET /api/check/:address
│   │   ├── validate-tx.ts    # POST /api/validate-tx
│   │   ├── threats.ts        # GET /api/threats
│   │   └── status.ts         # GET /api/status
│   ├── data/
│   │   ├── scam-addresses.ts # Known scam address database
│   │   └── threat-store.ts   # In-memory threat intelligence
│   └── test.ts               # Test suite
├── package.json
├── tsconfig.json
└── README.md
```

## Tech Stack

- **TypeScript** with ts-node
- **Express.js** — API framework
- **@solana/web3.js** — On-chain queries
- **Helmet** — Security headers
- **Rate limiting** — DDoS protection
- **Regex + heuristic analysis** — No ML dependencies, fast and deterministic

## License

MIT — Built by LobSec for the Colosseum Agent Hackathon.
