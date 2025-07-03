/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { FindingCorrelator } from './findingCorrelation.js';
import { SecurityFinding, FindingTypes } from '../types/security.js';

describe('FindingCorrelator', () => {
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

  describe('correlateFindings', () => {
    it('should remove exact duplicates by ID', () => {
      const finding1 = createTestFinding({ 
        id: 'duplicate-1',
        target: 'example1.com' // Different targets to avoid semantic deduplication
      });
      const finding2 = createTestFinding({ 
        id: 'duplicate-1', // Same ID
        target: 'example2.com'
      });
      const finding3 = createTestFinding({ 
        id: 'unique-1',
        target: 'example3.com'
      });

      const result = FindingCorrelator.correlateFindings([finding1, finding2, finding3]);

      expect(result.uniqueFindings).toHaveLength(2);
      expect(result.stats.originalCount).toBe(3);
      expect(result.stats.duplicatesRemoved).toBe(1);
    });

    it('should merge semantic duplicates', () => {
      const finding1 = createTestFinding({
        id: 'finding-1',
        target: 'example.com',
        type: FindingTypes.SERVICE_DISCOVERY,
        port: 80,
        evidence: ['evidence 1']
      });
      const finding2 = createTestFinding({
        id: 'finding-2',
        target: 'example.com',
        type: FindingTypes.SERVICE_DISCOVERY,
        port: 80,
        evidence: ['evidence 2'],
        severity: 'high' // Different severity but same semantic meaning
      });

      const result = FindingCorrelator.correlateFindings([finding1, finding2]);

      expect(result.uniqueFindings).toHaveLength(1);
      expect(result.correlatedGroups).toHaveLength(1);
      expect(result.correlatedGroups[0].type).toBe('duplicate');
      expect(result.correlatedGroups[0].confidence).toBe(1.0);
      
      // Should merge evidence
      const mergedFinding = result.uniqueFindings[0];
      expect(mergedFinding.evidence).toContain('evidence 1');
      expect(mergedFinding.evidence).toContain('evidence 2');
      
      // Should use higher severity
      expect(mergedFinding.severity).toBe('high');
    });

    it('should correlate related SSL/TLS findings', () => {
      const sslFinding = createTestFinding({
        id: 'ssl-1',
        target: 'example.com',
        type: FindingTypes.SSL_TLS_ISSUE,
        title: 'Weak SSL Configuration'
      });
      const certFinding = createTestFinding({
        id: 'cert-1',
        target: 'example.com',
        type: FindingTypes.CERTIFICATE_ISSUE,
        title: 'Expired Certificate'
      });
      const unrelatedFinding = createTestFinding({
        id: 'other-1',
        target: 'other.com',
        type: FindingTypes.SERVICE_DISCOVERY
      });

      const result = FindingCorrelator.correlateFindings([sslFinding, certFinding, unrelatedFinding]);

      expect(result.uniqueFindings).toHaveLength(1); // unrelatedFinding
      expect(result.correlatedGroups).toHaveLength(1);
      
      const correlatedGroup = result.correlatedGroups[0];
      expect(correlatedGroup.type).toBe('related');
      expect(correlatedGroup.confidence).toBe(0.8);
      expect(correlatedGroup.related).toHaveLength(1);
    });

    it('should identify attack chains', () => {
      const dnsFinding = createTestFinding({
        id: 'dns-1',
        target: 'subdomain.example.com',
        type: FindingTypes.DNS_MISCONFIGURATION,
        title: 'DNS Misconfiguration'
      });
      const takeoverFinding = createTestFinding({
        id: 'takeover-1',
        target: 'example.com',
        type: FindingTypes.SUBDOMAIN_TAKEOVER,
        title: 'Subdomain Takeover'
      });

      const result = FindingCorrelator.correlateFindings([dnsFinding, takeoverFinding]);

      expect(result.correlatedGroups).toHaveLength(1);
      
      const chain = result.correlatedGroups[0];
      expect(chain.type).toBe('chain');
      expect(chain.confidence).toBe(0.9);
    });

    it('should handle empty input', () => {
      const result = FindingCorrelator.correlateFindings([]);

      expect(result.uniqueFindings).toHaveLength(0);
      expect(result.correlatedGroups).toHaveLength(0);
      expect(result.stats.originalCount).toBe(0);
      expect(result.stats.duplicatesRemoved).toBe(0);
    });

    it('should normalize targets for comparison', () => {
      const finding1 = createTestFinding({
        id: 'finding-1',
        target: 'https://example.com/',
        type: FindingTypes.SERVICE_DISCOVERY,
        port: 80
      });
      const finding2 = createTestFinding({
        id: 'finding-2',
        target: 'example.com',
        type: FindingTypes.SERVICE_DISCOVERY,
        port: 80
      });

      const result = FindingCorrelator.correlateFindings([finding1, finding2]);

      // Should be treated as semantic duplicates
      expect(result.uniqueFindings).toHaveLength(1);
      expect(result.correlatedGroups).toHaveLength(1);
      expect(result.correlatedGroups[0].type).toBe('duplicate');
    });

    it('should preserve findings with different ports', () => {
      const finding1 = createTestFinding({
        id: 'finding-1',
        target: 'example.com',
        type: FindingTypes.SERVICE_DISCOVERY,
        port: 80
      });
      const finding2 = createTestFinding({
        id: 'finding-2',
        target: 'example.com',
        type: FindingTypes.SERVICE_DISCOVERY,
        port: 443
      });

      const result = FindingCorrelator.correlateFindings([finding1, finding2]);

      // Different ports should be separate findings
      expect(result.uniqueFindings).toHaveLength(2);
      expect(result.correlatedGroups).toHaveLength(0);
    });
  });

  describe('calculateGroupRiskScore', () => {
    it('should calculate risk score for correlation groups', () => {
      const primary = createTestFinding({ severity: 'high' });
      const related = [
        createTestFinding({ severity: 'medium' }),
        createTestFinding({ severity: 'low' })
      ];

      const group = {
        primary,
        related,
        confidence: 0.8,
        type: 'related' as const
      };

      const riskScore = FindingCorrelator.calculateGroupRiskScore(group);

      expect(riskScore).toBeGreaterThan(0);
      expect(riskScore).toBeLessThanOrEqual(10);
    });

    it('should apply higher multiplier for attack chains', () => {
      const primary = createTestFinding({ severity: 'medium' });
      const related = [createTestFinding({ severity: 'medium' })];

      const relatedGroup = {
        primary,
        related,
        confidence: 1.0,
        type: 'related' as const
      };

      const chainGroup = {
        primary,
        related,
        confidence: 1.0,
        type: 'chain' as const
      };

      const relatedScore = FindingCorrelator.calculateGroupRiskScore(relatedGroup);
      const chainScore = FindingCorrelator.calculateGroupRiskScore(chainGroup);

      expect(chainScore).toBeGreaterThan(relatedScore);
    });
  });
});