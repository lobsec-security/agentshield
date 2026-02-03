/**
 * In-memory threat intelligence store.
 * Stores recent detections, scan results, and flagged addresses.
 * In production, replace with a database.
 */

export interface ThreatEntry {
  id: string;
  type: 'scan_detection' | 'address_flag' | 'tx_block' | 'pattern_match';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  metadata: Record<string, any>;
  timestamp: string;
}

class ThreatStore {
  private threats: ThreatEntry[] = [];
  private maxSize = 10000;
  private stats = {
    totalScans: 0,
    totalAddressChecks: 0,
    totalTxValidations: 0,
    threatsDetected: 0,
    blockedTransactions: 0,
    startedAt: new Date().toISOString(),
  };

  addThreat(threat: Omit<ThreatEntry, 'id' | 'timestamp'>): ThreatEntry {
    const entry: ThreatEntry = {
      ...threat,
      id: this.generateId(),
      timestamp: new Date().toISOString(),
    };

    this.threats.unshift(entry);
    this.stats.threatsDetected++;

    // Trim if over max size
    if (this.threats.length > this.maxSize) {
      this.threats = this.threats.slice(0, this.maxSize);
    }

    return entry;
  }

  getThreats(since?: string, limit: number = 50): ThreatEntry[] {
    let results = this.threats;

    if (since) {
      const sinceDate = new Date(since);
      if (!isNaN(sinceDate.getTime())) {
        results = results.filter(t => new Date(t.timestamp) >= sinceDate);
      }
    }

    return results.slice(0, Math.min(limit, 200));
  }

  getStats() {
    return {
      ...this.stats,
      recentThreats: this.threats.length,
      uptimeMs: Date.now() - new Date(this.stats.startedAt).getTime(),
    };
  }

  incrementScans() { this.stats.totalScans++; }
  incrementAddressChecks() { this.stats.totalAddressChecks++; }
  incrementTxValidations() { this.stats.totalTxValidations++; }
  incrementBlocked() { this.stats.blockedTransactions++; }

  private generateId(): string {
    return `thr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  }
}

// Singleton
export const threatStore = new ThreatStore();
