/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { NetworkReconTool } from './network-recon.js';
import { exec } from 'child_process';
import { promisify } from 'util';

// Mock child_process exec
vi.mock('child_process', () => ({
  exec: vi.fn((cmd, opts, callback) => {
    // Handle both callback and options forms
    const cb = typeof opts === 'function' ? opts : callback;
    
    // Mock responses based on command
    if (cmd.includes('which nmap')) {
      cb?.(null, { stdout: '/usr/bin/nmap', stderr: '' });
    } else if (cmd.includes('which rustscan')) {
      cb?.(new Error('rustscan not found'), { stdout: '', stderr: 'command not found' });
    } else if (cmd.startsWith('nmap')) {
      // Return mock nmap XML output
      const xmlOutput = `<?xml version="1.0" encoding="UTF-8"?>
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
</nmaprun>`;
      cb?.(null, { stdout: xmlOutput, stderr: '' });
    } else {
      cb?.(new Error(`Unknown command: ${cmd}`), { stdout: '', stderr: '' });
    }
  })
}));

// Mock MemoryFindingStorage to prevent file system issues
vi.mock('../services/findingStorage.js', () => ({
  MemoryFindingStorage: {
    getInstance: vi.fn(() => ({
      storeFinding: vi.fn().mockResolvedValue(undefined)
    }))
  }
}));

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
  let mockExec: any;

  beforeEach(() => {
    vi.clearAllMocks();
    tool = new NetworkReconTool('/test/target');
    mockExec = vi.mocked(exec);
  });

  afterEach(() => {
    vi.restoreAllMocks();
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
      
      // Verify exec was called (tool checks rustscan first, then nmap)
      expect(mockExec).toHaveBeenCalledWith('which rustscan', expect.any(Function));
      expect(mockExec).toHaveBeenCalledWith('which nmap', expect.any(Function));
      expect(mockExec).toHaveBeenCalledWith(expect.stringContaining('nmap'), expect.any(Object), expect.any(Function));
    });

    it('should fall back to nmap when rustscan fails', async () => {
      // Update mock to fail rustscan but succeed with nmap
      mockExec.mockImplementation((cmd, opts, callback) => {
        const cb = typeof opts === 'function' ? opts : callback;
        
        if (cmd.includes('which rustscan')) {
          cb?.(new Error('rustscan not found'), { stdout: '', stderr: '' });
        } else if (cmd.includes('which nmap')) {
          cb?.(null, { stdout: '/usr/bin/nmap', stderr: '' });
        } else if (cmd.startsWith('nmap')) {
          const xmlOutput = `<?xml version="1.0" encoding="UTF-8"?>
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
</nmaprun>`;
          cb?.(null, { stdout: xmlOutput, stderr: '' });
        } else {
          cb?.(new Error(`Unknown command: ${cmd}`), { stdout: '', stderr: '' });
        }
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
      mockExec.mockImplementation((cmd, opts, callback) => {
        const cb = typeof opts === 'function' ? opts : callback;
        
        if (cmd.includes('which rustscan')) {
          cb?.(new Error('rustscan not found'), { stdout: '', stderr: '' });
        } else if (cmd.includes('which nmap')) {
          cb?.(null, { stdout: '/usr/bin/nmap', stderr: '' });
        } else if (cmd.startsWith('nmap')) {
          const xmlOutput = `<?xml version="1.0" encoding="UTF-8"?>
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
</nmaprun>`;
          cb?.(null, { stdout: xmlOutput, stderr: '' });
        } else {
          cb?.(new Error(`Unknown command: ${cmd}`), { stdout: '', stderr: '' });
        }
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
      mockExec.mockImplementation((cmd, opts, callback) => {
        const cb = typeof opts === 'function' ? opts : callback;
        
        if (cmd.includes('which rustscan')) {
          cb?.(new Error('rustscan not found'), { stdout: '', stderr: '' });
        } else if (cmd.includes('which nmap')) {
          cb?.(null, { stdout: '/usr/bin/nmap', stderr: '' });
        } else if (cmd.startsWith('nmap')) {
          const xmlOutput = `<?xml version="1.0" encoding="UTF-8"?>
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
</nmaprun>`;
          cb?.(null, { stdout: xmlOutput, stderr: '' });
        } else {
          cb?.(new Error(`Unknown command: ${cmd}`), { stdout: '', stderr: '' });
        }
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
      mockExec.mockImplementation((cmd, opts, callback) => {
        const cb = typeof opts === 'function' ? opts : callback;
        
        if (cmd.includes('which')) {
          cb?.(new Error('command not found'), { stdout: '', stderr: '' });
        }
      });

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
      mockExec.mockImplementation((cmd, opts, callback) => {
        const cb = typeof opts === 'function' ? opts : callback;
        
        if (cmd.includes('which rustscan')) {
          cb?.(new Error('rustscan not found'), { stdout: '', stderr: '' });
        } else if (cmd.includes('which nmap')) {
          cb?.(null, { stdout: '/usr/bin/nmap', stderr: '' });
        } else if (cmd.startsWith('nmap')) {
          // Verify the command has the expected arguments
          expect(cmd).toContain('-p-'); // Full port scan
          expect(cmd).toContain('-sV'); // Service detection
          expect(cmd).toContain('-O'); // OS detection
          expect(cmd).toContain('-T4'); // Aggressive timing
          expect(cmd).toContain('--max-rate=1000'); // Rate limiting
          
          const xmlOutput = `<?xml version="1.0" encoding="UTF-8"?>
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
</nmaprun>`;
          cb?.(null, { stdout: xmlOutput, stderr: '' });
        } else {
          cb?.(new Error(`Unknown command: ${cmd}`), { stdout: '', stderr: '' });
        }
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
    });

    it('should handle no open ports found', async () => {
      mockExec.mockImplementation((cmd, opts, callback) => {
        const cb = typeof opts === 'function' ? opts : callback;
        
        if (cmd.includes('which rustscan')) {
          cb?.(new Error('rustscan not found'), { stdout: '', stderr: '' });
        } else if (cmd.includes('which nmap')) {
          cb?.(null, { stdout: '/usr/bin/nmap', stderr: '' });
        } else if (cmd.startsWith('nmap')) {
          const xmlOutput = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.50"/>
    <ports>
    </ports>
  </host>
</nmaprun>`;
          cb?.(null, { stdout: xmlOutput, stderr: '' });
        } else {
          cb?.(new Error(`Unknown command: ${cmd}`), { stdout: '', stderr: '' });
        }
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
      mockExec.mockImplementation((cmd, opts, callback) => {
        const cb = typeof opts === 'function' ? opts : callback;
        
        if (cmd.includes('which rustscan')) {
          cb?.(new Error('rustscan not found'), { stdout: '', stderr: '' });
        } else if (cmd.includes('which nmap')) {
          cb?.(null, { stdout: '/usr/bin/nmap', stderr: '' });
        } else if (cmd.startsWith('nmap')) {
          const xmlOutput = `<?xml version="1.0"?><nmaprun><host><address addr="192.168.1.1"/></host></nmaprun>`;
          cb?.(null, { stdout: xmlOutput, stderr: '' });
        } else {
          cb?.(new Error(`Unknown command: ${cmd}`), { stdout: '', stderr: '' });
        }
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
      expect(description).toContain('Port scanning and service discovery');
      expect(description).toContain('service discovery');
    });
  });
});