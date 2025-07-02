/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

const mockWriteFile = vi.hoisted(() => vi.fn());
const mockReadFile = vi.hoisted(() => vi.fn());
const mockMkdir = vi.hoisted(() => vi.fn());

vi.mock('fs', () => ({
  promises: {
    writeFile: mockWriteFile,
    readFile: mockReadFile,
    mkdir: mockMkdir,
  },
}));

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MemoryFindingStorage } from './findingStorage.js';
import { SecurityFinding, FindingTypes } from '../types/security.js';

describe('MemoryFindingStorage', () => {
  let storage: MemoryFindingStorage;
  const targetDir = '/test/target';

  beforeEach(() => {
    // Reset all mocks
    mockWriteFile.mockReset();
    mockReadFile.mockReset();
    mockMkdir.mockReset();
    
    mockMkdir.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
    mockReadFile.mockRejectedValue(new Error('File not found')); // Default to empty state
    
    // Reset singleton instance
    (MemoryFindingStorage as any).instance = null;
    storage = MemoryFindingStorage.getInstance(targetDir);
  });

  describe('singleton pattern', () => {
    it('should return same instance for same target directory', () => {
      const storage1 = MemoryFindingStorage.getInstance(targetDir);
      const storage2 = MemoryFindingStorage.getInstance(targetDir);
      expect(storage1).toBe(storage2);
    });
  });

  describe('storeFinding', () => {
    it('should store a valid security finding', async () => {
      const finding: SecurityFinding = {
        id: 'test-finding-1',
        severity: 'high',
        type: FindingTypes.OPEN_PORT,
        target: '192.168.1.100',
        port: 22,
        protocol: 'tcp',
        title: 'SSH Service Exposed',
        description: 'SSH service is exposed on default port',
        impact: 'Potential unauthorized access',
        remediation: 'Restrict SSH access to authorized networks',
        evidence: ['Port 22/tcp open'],
        references: [],
        discoveredAt: new Date(),
        discoveredBy: 'NetworkReconTool',
        status: 'new'
      };

      await storage.storeFinding(finding);

      expect(mockMkdir).toHaveBeenCalledWith('/test/target/.spyglass', { recursive: true });
      expect(mockWriteFile).toHaveBeenCalledWith(
        '/test/target/.spyglass/findings.json',
        expect.stringContaining('"id": "test-finding-1"'),
        'utf8'
      );
    });

    it('should reject invalid findings', async () => {
      const invalidFinding = {
        id: 'invalid',
        severity: 'high'
        // Missing required fields
      } as any;

      await expect(storage.storeFinding(invalidFinding)).rejects.toThrow('Invalid security finding');
    });

    it('should update existing finding with same ID', async () => {
      const finding: SecurityFinding = {
        id: 'duplicate-test',
        severity: 'medium',
        type: FindingTypes.DNS_MISCONFIGURATION,
        target: 'example.com',
        title: 'DNS Issue',
        description: 'DNS configuration problem',
        impact: 'Information disclosure',
        remediation: 'Fix DNS settings',
        evidence: [],
        references: [],
        discoveredAt: new Date(),
        discoveredBy: 'ExternalReconTool',
        status: 'new'
      };

      // Store twice
      await storage.storeFinding(finding);
      await storage.storeFinding({ ...finding, severity: 'high' });

      expect(mockWriteFile).toHaveBeenCalledTimes(2);
    });
  });

  describe('getFindings', () => {
    it('should return empty array when no findings exist', async () => {
      const findings = await storage.getFindings();
      expect(findings).toEqual([]);
    });

    it('should load and return stored findings', async () => {
      const mockData = {
        version: '1.0',
        lastUpdated: new Date().toISOString(),
        findings: [{
          id: 'stored-finding',
          severity: 'critical',
          type: FindingTypes.VULNERABLE_SERVICE,
          target: 'vulnerable.example.com',
          title: 'Critical Vulnerability',
          description: 'Critical security issue found',
          impact: 'System compromise',
          remediation: 'Apply security patch',
          evidence: ['CVE-2023-12345'],
          references: [],
          discoveredAt: new Date().toISOString(),
          discoveredBy: 'VulnScanner',
          status: 'new'
        }]
      };

      mockReadFile.mockResolvedValueOnce(JSON.stringify(mockData));

      const findings = await storage.getFindings();
      expect(findings).toHaveLength(1);
      expect(findings[0].id).toBe('stored-finding');
      expect(findings[0].discoveredAt).toBeInstanceOf(Date);
    });

    it('should filter findings by severity', async () => {
      const mockData = {
        findings: [
          { id: '1', severity: 'critical', discoveredAt: new Date().toISOString() },
          { id: '2', severity: 'high', discoveredAt: new Date().toISOString() },
          { id: '3', severity: 'low', discoveredAt: new Date().toISOString() }
        ]
      };

      mockReadFile.mockResolvedValueOnce(JSON.stringify(mockData));

      const findings = await storage.getFindings({
        severities: ['critical', 'high']
      });

      expect(findings).toHaveLength(2);
      expect(findings.map(f => f.severity)).toEqual(['critical', 'high']);
    });

    it('should limit results when requested', async () => {
      const mockData = {
        findings: Array.from({ length: 10 }, (_, i) => ({
          id: `finding-${i}`,
          severity: 'medium',
          discoveredAt: new Date().toISOString()
        }))
      };

      mockReadFile.mockResolvedValueOnce(JSON.stringify(mockData));

      const findings = await storage.getFindings({ limit: 3 });
      expect(findings).toHaveLength(3);
    });
  });

  describe('getFindingStats', () => {
    it('should return correct statistics', async () => {
      const mockData = {
        findings: [
          { severity: 'critical', type: 'vuln', status: 'new', discoveredAt: '2025-01-01T00:00:00Z' },
          { severity: 'high', type: 'vuln', status: 'confirmed', discoveredAt: '2025-01-02T00:00:00Z' },
          { severity: 'medium', type: 'config', status: 'new', discoveredAt: '2025-01-03T00:00:00Z' }
        ]
      };

      mockReadFile.mockResolvedValueOnce(JSON.stringify(mockData));

      const stats = await storage.getFindingStats();

      expect(stats.total).toBe(3);
      expect(stats.bySeverity.critical).toBe(1);
      expect(stats.bySeverity.high).toBe(1);
      expect(stats.bySeverity.medium).toBe(1);
      expect(stats.byType.vuln).toBe(2);
      expect(stats.byType.config).toBe(1);
      expect(stats.byStatus.new).toBe(2);
      expect(stats.byStatus.confirmed).toBe(1);
    });
  });

  describe('exportFindings', () => {
    it('should export findings as JSON', async () => {
      const mockData = {
        findings: [
          { id: 'export-test', severity: 'high', discoveredAt: new Date().toISOString() }
        ]
      };

      mockReadFile.mockResolvedValueOnce(JSON.stringify(mockData));

      const exported = await storage.exportFindings('json');
      expect(exported).toContain('"id": "export-test"');
    });

    it('should export findings as summary', async () => {
      const mockData = {
        findings: [
          { severity: 'critical', discoveredAt: '2025-01-01T00:00:00Z' },
          { severity: 'high', discoveredAt: '2025-01-02T00:00:00Z' }
        ]
      };

      mockReadFile.mockResolvedValueOnce(JSON.stringify(mockData));

      const summary = await storage.exportFindings('summary');
      expect(summary).toContain('Total Findings: 2');
      expect(summary).toContain('Critical: 1');
      expect(summary).toContain('High: 1');
    });

    it('should handle unsupported export format', async () => {
      await expect(storage.exportFindings('xml' as any)).rejects.toThrow('Unsupported export format');
    });
  });

  describe('clearFindings', () => {
    it('should clear all findings', async () => {
      await storage.clearFindings();
      expect(mockWriteFile).toHaveBeenCalledWith(
        '/test/target/.spyglass/findings.json',
        expect.stringContaining('"findings": []'),
        'utf8'
      );
    });
  });
});