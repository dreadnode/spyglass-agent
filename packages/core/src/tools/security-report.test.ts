/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

const mockWriteFile = vi.hoisted(() => vi.fn());
const mockMkdir = vi.hoisted(() => vi.fn());

vi.mock('fs', () => ({
  promises: {
    writeFile: mockWriteFile,
    mkdir: mockMkdir,
  },
}));

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SecurityReportTool } from './security-report.js';

type SecurityReportParams = {
  title?: string;
  scope?: string[];
  assessor?: string;
  assessmentType?: 'network-scan' | 'external-recon' | 'full-assessment' | 'custom';
  format?: Array<'markdown' | 'json' | 'html'>;
  outputDir?: string;
  includeRawData?: boolean;
  aggregateFromMemory?: boolean;
  customFindings?: any[];
};

describe('SecurityReportTool', () => {
  let tool: SecurityReportTool;

  beforeEach(() => {
    // Reset all mocks
    mockWriteFile.mockReset();
    mockMkdir.mockReset();
    mockMkdir.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
    tool = new SecurityReportTool('/test/target');
  });

  describe('constructor', () => {
    it('should create tool with correct name and properties', () => {
      expect(tool.name).toBe('security_report');
      expect(tool.displayName).toBe('Security Assessment Report Generator');
      expect(tool.description).toContain('security assessment reports');
      expect(tool.description).toContain('aggregating findings');
    });
  });

  describe('execute', () => {
    it('should generate basic report with default parameters', async () => {
      const params: SecurityReportParams = {
        title: 'Test Security Report'
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('success');
      expect(result.returnDisplay).toContain('Security Report Generated');
      expect(mockMkdir).toHaveBeenCalledWith('./security-reports', { recursive: true });
      expect(mockWriteFile).toHaveBeenCalled();
    });

    it('should handle custom findings', async () => {
      const customFindings = [{
        id: 'test-finding-1',
        severity: 'high' as const,
        type: 'custom',
        target: 'test.example.com',
        title: 'Test Vulnerability',
        description: 'A test security finding',
        impact: 'High impact test',
        remediation: 'Fix the test issue'
      }];

      const params: SecurityReportParams = {
        title: 'Custom Findings Report',
        customFindings,
        format: ['markdown', 'json']
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('success');
      expect(result.returnDisplay).toContain('📊 Total Findings:** 1');
      expect(mockWriteFile).toHaveBeenCalledTimes(2); // markdown + json
    });

    it('should generate multiple formats', async () => {
      const params: SecurityReportParams = {
        title: 'Multi-Format Report',
        format: ['markdown', 'json', 'html']
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('success');
      expect(mockWriteFile).toHaveBeenCalledTimes(3); // All three formats
    });

    it('should handle different assessment types', async () => {
      const params: SecurityReportParams = {
        title: 'Network Scan Report',
        assessmentType: 'network-scan'
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('success');
      expect(result.returnDisplay).toContain('network-scan');
    });

    it('should handle custom output directory', async () => {
      const params: SecurityReportParams = {
        title: 'Custom Dir Report',
        outputDir: '/custom/reports'
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('success');
      expect(mockMkdir).toHaveBeenCalledWith('/custom/reports', { recursive: true });
    });

    it('should handle errors gracefully', async () => {
      mockWriteFile.mockRejectedValue(new Error('Write failed'));

      const params: SecurityReportParams = {
        title: 'Error Test Report'
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('"success":false');
      expect(result.returnDisplay).toContain('failed');
    });
  });

  describe('report generation', () => {
    it('should create proper risk ratings', async () => {
      const criticalFinding = {
        id: 'critical-1',
        severity: 'critical' as const,
        type: 'vulnerability',
        target: 'test.com',
        title: 'Critical Issue',
        description: 'A critical security issue',
        impact: 'System compromise',
        remediation: 'Immediate fix required'
      };

      const params: SecurityReportParams = {
        title: 'Risk Rating Test',
        customFindings: [criticalFinding]
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('success');
      expect(result.returnDisplay).toContain('CRITICAL');
    });

    it('should include raw data when requested', async () => {
      const params: SecurityReportParams = {
        title: 'Raw Data Report',
        includeRawData: true
      };

      const result = await tool.execute(params, new AbortController().signal);

      expect(result.llmContent).toContain('success');
      // Raw data would be included in appendices
    });
  });
});