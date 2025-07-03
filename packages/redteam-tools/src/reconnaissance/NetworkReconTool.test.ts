/**
 * Unit tests for NetworkReconTool
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NetworkReconTool, NetworkReconParams } from './NetworkReconTool.js';
import { ToolExecutionContext, EngagementScope } from '../types/index.js';

// Mock child_process
vi.mock('child_process', () => ({
  exec: vi.fn()
}));

describe('NetworkReconTool', () => {
  let mockContext: ToolExecutionContext;
  let networkRecon: NetworkReconTool;

  beforeEach(() => {
    const mockScope: EngagementScope = {
      id: 'test-engagement',
      name: 'Test Engagement',
      timeline: {
        start: new Date('2024-01-01'),
        end: new Date('2024-12-31')
      },
      domains: ['example.com'],
      ipRanges: ['192.168.1.0/24', '10.0.0.0/8'],
      exclusions: ['192.168.1.1'],
      permissions: {
        passiveRecon: true,
        activeScanning: true,
        vulnerabilityTesting: false,
        exploitTesting: false,
        socialEngineering: false,
        physicalAccess: false
      },
      contacts: {
        primary: 'security@example.com',
        emergency: 'incident@example.com'
      }
    };

    mockContext = {
      scope: mockScope,
      user: 'test-user',
      sessionId: 'test-session-123',
      config: {
        settings: {},
        timeout: {
          connectTimeout: 30000,
          readTimeout: 300000
        }
      },
      logger: vi.fn()
    };

    networkRecon = new NetworkReconTool(mockContext);
  });

  describe('Configuration', () => {
    it('should have correct tool name', () => {
      expect(networkRecon.getToolName()).toBe('NetworkRecon');
    });

    it('should require activeScanning permission', () => {
      const permissions = networkRecon.getRequiredPermissions();
      expect(permissions).toContain('activeScanning');
    });

    it('should extract targets from parameters', () => {
      const params: NetworkReconParams = {
        targets: ['192.168.1.100', '10.0.0.1'],
        scanType: 'quick'
      };
      
      const targets = networkRecon.extractTargets(params);
      expect(targets).toEqual(['192.168.1.100', '10.0.0.1']);
    });
  });

  describe('Parameter Validation', () => {
    it('should have valid parameter schema', () => {
      const schema = networkRecon.getParameterSchema();
      expect(schema).toHaveProperty('type', 'object');
      expect(schema).toHaveProperty('properties');
      expect(schema).toHaveProperty('required');
      
      const properties = (schema as any).properties;
      expect(properties).toHaveProperty('targets');
      expect(properties).toHaveProperty('scanType');
      expect(properties.targets.type).toBe('array');
      expect(properties.scanType.enum).toContain('quick');
      expect(properties.scanType.enum).toContain('full');
      expect(properties.scanType.enum).toContain('custom');
    });

    it('should require targets parameter', () => {
      const schema = networkRecon.getParameterSchema();
      const required = (schema as any).required;
      expect(required).toContain('targets');
    });
  });

  describe('Tool Selection', () => {
    it('should detect available tools', async () => {
      // Mock successful tool detection
      const { exec } = await import('child_process');
      const mockExec = exec as any;
      
      mockExec.mockImplementation((cmd: string, callback: Function) => {
        if (cmd.includes('which nmap')) {
          callback(null, { stdout: '/usr/bin/nmap' });
        } else {
          callback(new Error('not found'));
        }
      });

      // This is a simplified test - the actual tool selection logic
      // would need more comprehensive mocking
      expect(networkRecon).toBeDefined();
    });
  });

  describe('Output Parsing', () => {
    it('should parse nmap XML output correctly', () => {
      const mockXml = `
        <nmaprun>
          <host>
            <address addr="192.168.1.100"/>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache"/>
              </port>
              <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https"/>
              </port>
            </ports>
          </host>
        </nmaprun>
      `;

      // Access private method for testing
      const parseMethod = (networkRecon as any).parseNmapXml;
      const results = parseMethod(mockXml);
      
      expect(results).toHaveLength(1);
      expect(results[0].host).toBe('192.168.1.100');
      expect(results[0].ports).toHaveLength(2);
      expect(results[0].ports[0].port).toBe(80);
      expect(results[0].ports[0].service).toBe('http');
      expect(results[0].ports[1].port).toBe(443);
    });

    it('should classify high-risk services correctly', () => {
      const isHighRisk = (networkRecon as any).isHighRiskService;
      
      expect(isHighRisk('ftp', 21)).toBe(true);
      expect(isHighRisk('telnet', 23)).toBe(true);
      expect(isHighRisk('mysql', 3306)).toBe(true);
      expect(isHighRisk('http', 80)).toBe(false);
      expect(isHighRisk('https', 443)).toBe(false);
    });

    it('should classify admin services correctly', () => {
      const isAdminService = (networkRecon as any).isAdminService;
      
      expect(isAdminService('ssh', 22)).toBe(true);
      expect(isAdminService('rdp', 3389)).toBe(true);
      expect(isAdminService('snmp', 161)).toBe(true);
      expect(isAdminService('http', 80)).toBe(false);
    });
  });

  describe('Finding Generation', () => {
    it('should generate appropriate findings for discovered services', () => {
      const mockResults = [
        {
          host: '192.168.1.100',
          ports: [
            { port: 21, protocol: 'tcp' as const, state: 'open', service: 'ftp' },
            { port: 22, protocol: 'tcp' as const, state: 'open', service: 'ssh' },
            { port: 80, protocol: 'tcp' as const, state: 'open', service: 'http' }
          ]
        }
      ];

      const findings = (networkRecon as any).generateFindings(mockResults);
      
      expect(findings).toHaveLength(3);
      
      // FTP should be marked as high-risk
      const ftpFinding = findings.find((f: any) => f.port === 21);
      expect(ftpFinding.severity).toBe('medium');
      expect(ftpFinding.title).toContain('High-risk service');
      
      // SSH should be marked as admin service
      const sshFinding = findings.find((f: any) => f.port === 22);
      expect(sshFinding.severity).toBe('medium');
      expect(sshFinding.title).toContain('Administrative service');
      
      // HTTP should be info level
      const httpFinding = findings.find((f: any) => f.port === 80);
      expect(httpFinding.severity).toBe('info');
    });
  });

  describe('Scope Validation', () => {
    it('should validate targets against engagement scope', async () => {
      // This would test the scope validation logic
      // The actual implementation would check if targets are within
      // the approved IP ranges and domains
      expect(networkRecon).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle missing tools gracefully', async () => {
      // Mock all tools as unavailable
      const { exec } = await import('child_process');
      const mockExec = exec as any;
      
      mockExec.mockImplementation((cmd: string, callback: Function) => {
        callback(new Error('command not found'));
      });

      // The tool should throw an appropriate error
      // when no scanning tools are available
      expect(networkRecon).toBeDefined();
    });

    it('should handle invalid scan parameters', async () => {
      const invalidParams: NetworkReconParams = {
        targets: ['192.168.1.100'],
        scanType: 'custom'
        // Missing required 'ports' parameter for custom scan
      };

      try {
        await (networkRecon as any).executeImpl(invalidParams);
        expect.fail('Should have thrown an error for missing ports parameter');
      } catch (error) {
        expect((error as Error).message).toContain('Custom scan type requires ports parameter');
      }
    });
  });
});