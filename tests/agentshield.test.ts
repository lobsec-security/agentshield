/**
 * AgentShield Test Suite
 */

import { describe, it, expect } from '@jest/globals';

// Import types/interfaces (adjust based on actual exports)
// import { AgentShield, ScanResult } from '../src/index';

describe('AgentShield', () => {
    describe('Module Loading', () => {
        it('should export main module', () => {
            const agentshield = require('../src/index');
            expect(agentshield).toBeDefined();
        });
    });

    describe('Scanner Configuration', () => {
        it('should accept valid configuration', () => {
            const config = {
                enableAddressCheck: true,
                enablePatternDetection: true,
                riskThreshold: 0.7
            };
            expect(config.enableAddressCheck).toBe(true);
        });

        it('should have sensible defaults', () => {
            const defaultThreshold = 0.5;
            expect(defaultThreshold).toBeGreaterThan(0);
            expect(defaultThreshold).toBeLessThanOrEqual(1);
        });
    });

    describe('Risk Levels', () => {
        it('should define risk levels', () => {
            const riskLevels = ['low', 'medium', 'high', 'critical'];
            expect(riskLevels).toContain('low');
            expect(riskLevels).toContain('critical');
        });

        it('should order risk levels correctly', () => {
            const riskOrder = { low: 1, medium: 2, high: 3, critical: 4 };
            expect(riskOrder.low).toBeLessThan(riskOrder.high);
            expect(riskOrder.high).toBeLessThan(riskOrder.critical);
        });
    });

    describe('Address Validation', () => {
        it('should validate Ethereum address format', () => {
            const validAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD87';
            const isValid = /^0x[a-fA-F0-9]{40}$/.test(validAddress);
            expect(isValid).toBe(true);
        });

        it('should reject invalid addresses', () => {
            const invalidAddress = 'not-an-address';
            const isValid = /^0x[a-fA-F0-9]{40}$/.test(invalidAddress);
            expect(isValid).toBe(false);
        });
    });

    describe('Pattern Detection', () => {
        it('should detect shell execution patterns', () => {
            const dangerousPatterns = [
                /eval\s*\(/,
                /exec\s*\(/,
                /os\.system/,
                /subprocess\./
            ];
            const testCode = 'os.system("rm -rf /")';
            const detected = dangerousPatterns.some(p => p.test(testCode));
            expect(detected).toBe(true);
        });

        it('should not flag safe code', () => {
            const dangerousPatterns = [
                /eval\s*\(/,
                /exec\s*\(/
            ];
            const safeCode = 'console.log("Hello World")';
            const detected = dangerousPatterns.some(p => p.test(safeCode));
            expect(detected).toBe(false);
        });
    });
});
