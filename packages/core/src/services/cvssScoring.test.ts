/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { CvssScorer } from './cvssScoring.js';
import { SecurityFinding, FindingTypes } from '../types/security.js';

describe('CvssScorer', () => {
  const createTestFinding = (overrides: Partial<SecurityFinding> = {}): SecurityFinding => ({
    id: 'test-id',
    severity: 'medium',
    type: FindingTypes.SERVICE_DISCOVERY,
    target: 'example.com',
    title: 'Test Finding',
    description: 'Test description',
    impact: 'Test impact',
    remediation: 'Test remediation',
    evidence: ['test evidence'],
    references: ['test reference'],
    discoveredAt: new Date(),
    discoveredBy: 'TestTool',
    status: 'new',
    ...overrides
  });

  describe('calculateScore', () => {
    it('should calculate score for service discovery finding', () => {
      const finding = createTestFinding({
        type: FindingTypes.SERVICE_DISCOVERY,
        severity: 'low',
        description: 'HTTP service running on port 80',
        port: 80
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.score).toBeGreaterThan(0);
      expect(result.score).toBeLessThanOrEqual(10);
      expect(result.vector).toMatch(/^CVSS:3\.1\//);
      expect(result.metrics.attackVector).toBe('network');
    });

    it('should score RCE vulnerabilities as high', () => {
      const finding = createTestFinding({
        type: 'remote-code-execution',
        severity: 'critical',
        description: 'Remote code execution vulnerability allows arbitrary command execution',
        title: 'Remote Code Execution'
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.score).toBeGreaterThanOrEqual(7.0);
      expect(result.metrics.scope).toBe('changed');
      expect(result.metrics.integrityImpact).toBe('high');
    });

    it('should score default credentials appropriately', () => {
      const finding = createTestFinding({
        type: FindingTypes.DEFAULT_CREDENTIALS,
        severity: 'high',
        description: 'Default admin password admin:admin found',
        title: 'Default Credentials'
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.score).toBeGreaterThanOrEqual(5.0);
      expect(result.metrics.privilegesRequired).toBe('none');
      expect(result.metrics.confidentialityImpact).toBe('high');
      expect(result.metrics.integrityImpact).toBe('high');
    });

    it('should score SSL/TLS issues correctly', () => {
      const finding = createTestFinding({
        type: FindingTypes.SSL_TLS_ISSUE,
        severity: 'medium',
        description: 'Weak SSL cipher suites detected',
        title: 'Weak SSL Configuration',
        port: 443
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.score).toBeGreaterThan(0);
      expect(result.metrics.confidentialityImpact).toBe('low');
      expect(result.metrics.integrityImpact).toBe('low');
    });

    it('should handle information disclosure findings', () => {
      const finding = createTestFinding({
        type: FindingTypes.INFORMATION_DISCLOSURE,
        severity: 'medium',
        description: 'Directory listing reveals sensitive files',
        title: 'Directory Listing Enabled'
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.score).toBeGreaterThan(0);
      expect(result.metrics.confidentialityImpact).toBe('low');
    });

    it('should detect user interaction requirements', () => {
      const finding = createTestFinding({
        type: 'xss',
        severity: 'medium',
        description: 'XSS vulnerability requires user to click malicious link',
        title: 'Reflected XSS'
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.metrics.userInteraction).toBe('required');
      expect(result.metrics.scope).toBe('changed');
    });

    it('should identify local attack vectors', () => {
      const finding = createTestFinding({
        type: 'local-privilege-escalation',
        severity: 'high',
        description: 'Local privilege escalation via SUID binary',
        title: 'Local Privilege Escalation'
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.metrics.attackVector).toBe('local');
    });

    it('should detect high attack complexity', () => {
      const finding = createTestFinding({
        type: 'race-condition',
        severity: 'medium',
        description: 'Complex race condition vulnerability in file handling',
        title: 'Race Condition'
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.metrics.attackComplexity).toBe('high');
    });

    it('should handle DoS vulnerabilities', () => {
      const finding = createTestFinding({
        type: 'denial-of-service',
        severity: 'medium',
        description: 'Resource exhaustion leads to service crash',
        title: 'DoS via Resource Exhaustion'
      });

      const result = CvssScorer.calculateScore(finding);

      expect(result.metrics.availabilityImpact).toBe('high');
    });
  });

  describe('scoreFinding', () => {
    it('should add CVSS score and vector to finding', () => {
      const finding = createTestFinding({
        type: FindingTypes.VULNERABLE_SERVICE,
        severity: 'high'
      });

      const scoredFinding = CvssScorer.scoreFinding(finding);

      expect(scoredFinding.cvssScore).toBeDefined();
      expect(scoredFinding.cvssVector).toBeDefined();
      expect(scoredFinding.cvssScore).toBeGreaterThan(0);
      expect(scoredFinding.cvssVector).toMatch(/^CVSS:3\.1\//);
    });
  });

  describe('scoreFindings', () => {
    it('should score multiple findings', () => {
      const findings = [
        createTestFinding({ type: FindingTypes.SERVICE_DISCOVERY }),
        createTestFinding({ type: FindingTypes.VULNERABLE_SERVICE }),
        createTestFinding({ type: FindingTypes.DEFAULT_CREDENTIALS })
      ];

      const scoredFindings = CvssScorer.scoreFindings(findings);

      expect(scoredFindings).toHaveLength(3);
      scoredFindings.forEach(finding => {
        expect(finding.cvssScore).toBeDefined();
        expect(finding.cvssVector).toBeDefined();
        expect(finding.cvssScore).toBeGreaterThanOrEqual(0);
        expect(finding.cvssScore).toBeLessThanOrEqual(10);
      });
    });
  });

  describe('calculateRiskLevel', () => {
    it('should calculate enhanced risk for network exposed services', () => {
      const finding = createTestFinding({
        type: FindingTypes.VULNERABLE_SERVICE,
        severity: 'medium',
        port: 22
      });

      const risk = CvssScorer.calculateRiskLevel(finding);

      expect(risk.riskScore).toBeGreaterThan(0);
      expect(risk.factors).toContain('Network exposed service');
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(risk.riskLevel);
    });

    it('should calculate high risk for default credentials', () => {
      const finding = createTestFinding({
        type: FindingTypes.DEFAULT_CREDENTIALS,
        severity: 'medium'
      });

      const risk = CvssScorer.calculateRiskLevel(finding);

      expect(risk.factors).toContain('Default credentials present');
      expect(risk.riskScore).toBeGreaterThan(3.0);
    });

    it('should calculate critical risk for RCE', () => {
      const finding = createTestFinding({
        type: 'remote-code-execution',
        severity: 'high',
        description: 'Remote code execution via command injection'
      });

      const risk = CvssScorer.calculateRiskLevel(finding);

      expect(risk.factors).toContain('Remote code execution possible');
      expect(risk.riskLevel).toBeOneOf(['critical', 'high']);
    });

    it('should enhance risk for information disclosure', () => {
      const finding = createTestFinding({
        type: FindingTypes.INFORMATION_DISCLOSURE,
        severity: 'low'
      });

      const risk = CvssScorer.calculateRiskLevel(finding);

      expect(risk.factors).toContain('Information disclosure');
    });

    it('should enhance risk for SSL/TLS issues on network services', () => {
      const finding = createTestFinding({
        type: FindingTypes.SSL_TLS_ISSUE,
        severity: 'low',
        port: 443
      });

      const risk = CvssScorer.calculateRiskLevel(finding);

      expect(risk.factors).toContain('Cryptographic weakness');
      expect(risk.factors).toContain('Network exposed service');
    });

    it('should cap risk score at 10.0', () => {
      const finding = createTestFinding({
        type: 'remote-code-execution',
        severity: 'critical',
        description: 'Remote code execution with default credentials',
        port: 22
      });

      const risk = CvssScorer.calculateRiskLevel(finding);

      expect(risk.riskScore).toBeLessThanOrEqual(10.0);
    });

    it('should return info level for zero-impact findings', () => {
      const finding = createTestFinding({
        type: 'informational',
        severity: 'info',
        description: 'Server banner information'
      });

      const risk = CvssScorer.calculateRiskLevel(finding);

      expect(risk.riskLevel).toBe('info');
    });
  });

  describe('CVSS vector generation', () => {
    it('should generate valid CVSS v3.1 vectors', () => {
      const findings = [
        createTestFinding({ type: FindingTypes.SERVICE_DISCOVERY }),
        createTestFinding({ type: FindingTypes.DEFAULT_CREDENTIALS }),
        createTestFinding({ type: 'sql-injection', severity: 'high' })
      ];

      findings.forEach(finding => {
        const result = CvssScorer.calculateScore(finding);
        
        // Should start with CVSS:3.1
        expect(result.vector).toMatch(/^CVSS:3\.1/);
        
        // Should contain all required metrics
        expect(result.vector).toMatch(/AV:[NALP]/);
        expect(result.vector).toMatch(/AC:[LH]/);
        expect(result.vector).toMatch(/PR:[NLH]/);
        expect(result.vector).toMatch(/UI:[NR]/);
        expect(result.vector).toMatch(/S:[UC]/);
        expect(result.vector).toMatch(/C:[NLH]/);
        expect(result.vector).toMatch(/I:[NLH]/);
        expect(result.vector).toMatch(/A:[NLH]/);
      });
    });
  });
});