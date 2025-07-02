/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

const mockExecAsync = vi.hoisted(() => vi.fn());

vi.mock('child_process', () => ({
  exec: vi.fn(),
}));

vi.mock('util', () => ({
  promisify: vi.fn((fn) => {
    if (fn.name === 'exec') return mockExecAsync;
    return fn;
  }),
}));

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NetworkReconTool } from './network-recon.js';

type NetworkReconParams = {
  targets: string[];
  scanType?: 'quick' | 'full' | 'custom';
  ports?: string;
  osDetection?: boolean;
  serviceDetection?: boolean;
  aggressiveTiming?: boolean;
  preferredTool?: 'nmap' | 'rustscan' | 'auto';
  maxRate?: number;
};

describe('NetworkReconTool', () => {
  let tool: NetworkReconTool;

  beforeEach(() => {
    // Reset all mocks
    mockExecAsync.mockReset();
    tool = new NetworkReconTool();
  });

  describe('constructor', () => {
    it('should create tool with correct name and properties', () => {
      expect(tool.name).toBe('network_recon');
      expect(tool.displayName).toBe('Network Reconnaissance');
      expect(tool.description).toContain('network reconnaissance');
      expect(tool.description).toContain('nmap');
    });
  });

  describe('execute', () => {
    it('should successfully perform nmap scan', async () => {
      // Mock 'which nmap' to return success
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '/usr/bin/nmap', stderr: '' })
        .mockResolvedValueOnce({
          stdout: `
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41"/>
      </port>
    </ports>
  </host>
</nmaprun>
          `,
          stderr: ''
        });

      const params: NetworkReconParams = {
        targets: ['192.168.1.1'],
        scanType: 'quick',
        serviceDetection: true
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(parsedResult.tool).toBe('network_recon');
      expect(parsedResult.openPorts).toBe(2);
      expect(result.returnDisplay).toContain('Network Reconnaissance Results');
      expect(result.returnDisplay).toContain('192.168.1.1');
      expect(result.returnDisplay).toContain('ssh');
      expect(result.returnDisplay).toContain('http');
    });

    it('should fall back to nmap when rustscan fails', async () => {
      // Mock 'which rustscan' to fail, 'which nmap' to succeed
      mockExecAsync
        .mockRejectedValueOnce(new Error('rustscan not found'))
        .mockResolvedValueOnce({ stdout: '/usr/bin/nmap', stderr: '' })
        .mockResolvedValueOnce({
          stdout: `
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
          `,
          stderr: ''
        });

      const params: NetworkReconParams = {
        targets: ['10.0.0.1'],
        preferredTool: 'rustscan'
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(parsedResult.data.toolUsed).toBe('nmap');
      expect(result.returnDisplay).toContain('https');
    });

    it('should perform custom port scan', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '/usr/bin/nmap', stderr: '' })
        .mockResolvedValueOnce({
          stdout: `
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.30"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy"/>
      </port>
      <port protocol="tcp" portid="8443">
        <state state="open"/>
        <service name="https-alt"/>
      </port>
    </ports>
  </host>
</nmaprun>
          `,
          stderr: ''
        });

      const params: NetworkReconParams = {
        targets: ['192.168.1.30'],
        scanType: 'custom',
        ports: '8080,8443'
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(result.returnDisplay).toContain('8080');
      expect(result.returnDisplay).toContain('8443');
    });

    it('should generate security findings for high-risk services', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '/usr/bin/nmap', stderr: '' })
        .mockResolvedValueOnce({
          stdout: `
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.40"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>
          `,
          stderr: ''
        });

      const params: NetworkReconParams = {
        targets: ['192.168.1.40']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(parsedResult.findings).toBeGreaterThan(0);
      expect(result.returnDisplay).toContain('Security Findings');
      expect(result.returnDisplay).toContain('Priority Findings');
    });

    it('should validate custom scan requires ports parameter', async () => {
      const params: NetworkReconParams = {
        targets: ['192.168.1.1'],
        scanType: 'custom'
        // Missing ports parameter
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(false);
      expect(result.returnDisplay).toContain('Custom scan type requires ports parameter');
    });

    it('should handle tool not available error', async () => {
      // Mock both tools as unavailable
      mockExecAsync
        .mockRejectedValueOnce(new Error('rustscan not found'))
        .mockRejectedValueOnce(new Error('nmap not found'));

      const params: NetworkReconParams = {
        targets: ['192.168.1.1']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(false);
      expect(result.returnDisplay).toContain('Network reconnaissance failed');
      expect(result.returnDisplay).toContain('nmap or rustscan');
    });

    it('should apply scan options correctly', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '/usr/bin/nmap', stderr: '' })
        .mockResolvedValueOnce({
          stdout: `
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.60"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
          `,
          stderr: ''
        });

      const params: NetworkReconParams = {
        targets: ['192.168.1.60'],
        scanType: 'full',
        osDetection: true,
        serviceDetection: true,
        aggressiveTiming: true,
        maxRate: 1000
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      
      // Verify nmap was called with correct arguments
      const nmapCall = mockExecAsync.mock.calls[1][0];
      expect(nmapCall).toContain('-p-'); // Full port scan
      expect(nmapCall).toContain('-sV'); // Service detection
      expect(nmapCall).toContain('-O'); // OS detection
      expect(nmapCall).toContain('-T4'); // Aggressive timing
      expect(nmapCall).toContain('--max-rate=1000'); // Rate limiting
    });

    it('should handle no open ports found', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '/usr/bin/nmap', stderr: '' })
        .mockResolvedValueOnce({
          stdout: `
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.50"/>
    <ports>
    </ports>
  </host>
</nmaprun>
          `,
          stderr: ''
        });

      const params: NetworkReconParams = {
        targets: ['192.168.1.50']
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
      expect(parsedResult.openPorts).toBe(0);
      expect(result.returnDisplay).toContain('No Open Ports Found');
    });
  });

  describe('parameter validation', () => {
    it('should require targets parameter', async () => {
      const params = {} as any;

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(false);
    });

    it('should accept valid scan types', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '/usr/bin/nmap', stderr: '' })
        .mockResolvedValueOnce({
          stdout: `<?xml version="1.0"?><nmaprun><host><address addr="192.168.1.1"/></host></nmaprun>`,
          stderr: ''
        });

      const params: NetworkReconParams = {
        targets: ['192.168.1.1'],
        scanType: 'quick'
      };

      const result = await tool.execute(params, new AbortController().signal);
      const parsedResult = JSON.parse(result.llmContent as string);

      expect(parsedResult.success).toBe(true);
    });
  });

  describe('getDescription', () => {
    it('should return tool description', () => {
      const description = tool.description;
      expect(description).toContain('network reconnaissance');
      expect(description).toContain('port scanning');
      expect(description).toContain('service discovery');
    });
  });
}); 