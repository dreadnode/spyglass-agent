/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

const mockExecAsync = vi.hoisted(() => vi.fn());
const mockDnsResolve4 = vi.hoisted(() => vi.fn());
const mockDnsResolveMx = vi.hoisted(() => vi.fn());
const mockDnsResolveTxt = vi.hoisted(() => vi.fn());
const mockDnsResolveNs = vi.hoisted(() => vi.fn());
const mockDnsResolveCname = vi.hoisted(() => vi.fn());
const mockDnsSetServers = vi.hoisted(() => vi.fn());

vi.mock('child_process', () => ({
  exec: vi.fn(),
}));

vi.mock('util', () => ({
  promisify: vi.fn((fn) => {
    if (fn.name === 'exec') return mockExecAsync;
    return fn;
  }),
}));

vi.mock('dns', () => ({
  resolve4: mockDnsResolve4,
  resolveMx: mockDnsResolveMx,
  resolveTxt: mockDnsResolveTxt,
  resolveNs: mockDnsResolveNs,
  resolveCname: mockDnsResolveCname,
  setServers: mockDnsSetServers,
}));

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ExternalReconTool } from './external-recon.js';

type ExternalReconParams = {
  domains: string[];
  reconTypes?: Array<'whois' | 'dns' | 'subdomain' | 'all'>;
  zoneTransfer?: boolean;
  useExternalApis?: boolean;
  dnsServer?: string;
  subdomainDepth?: number;
  subdomainWordlist?: 'small' | 'medium' | 'large';
};

describe('ExternalReconTool', () => {
  let tool: ExternalReconTool;

  beforeEach(() => {
    // Reset all mocks
    mockExecAsync.mockReset();
    mockDnsResolve4.mockReset();
    mockDnsResolveMx.mockReset();
    mockDnsResolveTxt.mockReset();
    mockDnsResolveNs.mockReset();
    mockDnsResolveCname.mockReset();
    mockDnsSetServers.mockReset();

    tool = new ExternalReconTool('/test/target');
  });

  describe('constructor', () => {
    it('should create tool with correct name and properties', () => {
      expect(tool.name).toBe('external_recon');
      expect(tool.displayName).toBe('External Reconnaissance');
      expect(tool.description).toContain('Performs comprehensive external reconnaissance');
    });
  });

  describe('execute', () => {
    it('should successfully perform WHOIS reconnaissance', async () => {
      const mockWhoisOutput = `
Registrar: Example Registrar
Creation Date: 2020-01-01T00:00:00Z
Expiry Date: 2025-01-01T00:00:00Z
Name Server: ns1.example.com
DNSSEC: unsigned
      `;

      mockExecAsync.mockResolvedValueOnce({ 
        stdout: mockWhoisOutput, 
        stderr: '' 
      });

      const params: ExternalReconParams = {
        domains: ['example.com'],
        reconTypes: ['whois']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(parsedResult.tool).toBe('external_recon');
      expect(parsedResult.domains).toBe(1);
      expect(result.returnDisplay).toContain('External Reconnaissance Results');
      expect(result.returnDisplay).toContain('example.com');
    });

    it('should perform DNS enumeration', async () => {
      // Mock DNS responses
      mockDnsResolve4.mockResolvedValueOnce(['192.168.1.1', '192.168.1.2']);
      mockDnsResolveMx.mockResolvedValueOnce([
        { priority: 10, exchange: 'mail.example.com' },
        { priority: 20, exchange: 'mail2.example.com' }
      ]);
      mockDnsResolveTxt.mockResolvedValueOnce([
        ['v=spf1 include:_spf.example.com ~all'],
        ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']
      ]);
      mockDnsResolveNs.mockResolvedValueOnce(['ns1.example.com', 'ns2.example.com']);
      mockDnsResolveCname.mockRejectedValueOnce(new Error('No CNAME'));

      // Mock dig commands
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '2001:db8::1\n', stderr: '' }) // AAAA
        .mockResolvedValueOnce({ stdout: 'ns1.example.com. admin.example.com. 1 3600 1800 604800 86400', stderr: '' }); // SOA

      const params: ExternalReconParams = {
        domains: ['example.com'],
        reconTypes: ['dns']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(result.returnDisplay).toContain('DNS Records');
      expect(result.returnDisplay).toContain('192.168.1.1');
      expect(result.returnDisplay).toContain('mail.example.com');
    });

    it('should handle tool availability errors', async () => {
      // Mock unavailable external tools
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const params: ExternalReconParams = {
        domains: ['example.com'],
        reconTypes: ['whois']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      // Tool handles graceful degradation when external tools aren't available
      expect(parsedResult.success).toBe(true);
      expect(result.returnDisplay).toContain('External reconnaissance completed');
    });

    it('should handle multiple domains', async () => {
      mockDnsResolve4.mockResolvedValue(['192.168.1.1']);

      const params: ExternalReconParams = {
        domains: ['example.com', 'test.org'],
        reconTypes: ['dns']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(parsedResult.domains).toBe(2);
      expect(result.returnDisplay).toContain('example.com');
      expect(result.returnDisplay).toContain('test.org');
    });

    it('should use custom DNS server when specified', async () => {
      mockDnsResolve4.mockResolvedValueOnce(['8.8.8.8']);

      const params: ExternalReconParams = {
        domains: ['example.com'],
        reconTypes: ['dns'],
        dnsServer: '8.8.8.8'
      };

      await tool.execute(params, new AbortController().signal);

      expect(mockDnsSetServers).toHaveBeenCalledWith(['8.8.8.8']);
    });
  });

  describe('parameter validation', () => {
    it('should require domains parameter', async () => {
      const params = {} as any;

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(false);
    });

    it('should accept valid recon types', async () => {
      mockDnsResolve4.mockResolvedValueOnce(['192.168.1.1']);

      const params: ExternalReconParams = {
        domains: ['example.com'],
        reconTypes: ['whois', 'dns', 'subdomain']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
    });
  });

  describe('getDescription', () => {
    it('should return tool description', () => {
      const description = tool.description;
      expect(description).toContain('external reconnaissance');
      expect(description).toContain('DNS record enumeration');
      expect(description).toContain('WHOIS information');
    });
  });
}); 