/**
 * Network Reconnaissance Tool
 * 
 * Wraps nmap and rustscan for intelligent network discovery and port scanning
 * with proper scope validation and structured output.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { RedTeamTool } from '../base/RedTeamTool.js';
import { EngagementScope, ToolExecutionResult, ReconData, SecurityFinding } from '../types/index.js';
import * as net from 'net';

const execAsync = promisify(exec);

export interface NetworkReconParams {
  /** Target IP addresses or CIDR ranges */
  targets: string[];
  /** Scan type: quick, full, or custom */
  scanType: 'quick' | 'full' | 'custom';
  /** Specific ports to scan (for custom scan type) */
  ports?: string;
  /** Whether to perform OS detection */
  osDetection?: boolean;
  /** Whether to perform service version detection */
  serviceDetection?: boolean;
  /** Whether to use aggressive timing */
  aggressiveTiming?: boolean;
  /** Preferred scanning tool */
  preferredTool?: 'nmap' | 'rustscan' | 'auto';
  /** Maximum scan rate (packets per second) */
  maxRate?: number;
}

interface NmapResult {
  host: string;
  ports: Array<{
    port: number;
    protocol: 'tcp' | 'udp';
    state: string;
    service: string;
    version?: string;
    banner?: string;
  }>;
  osInfo?: {
    name: string;
    accuracy: number;
  };
}

export class NetworkReconTool extends RedTeamTool {
  getToolName(): string {
    return 'NetworkRecon';
  }

  getDescription(): string {
    return 'Performs network reconnaissance using nmap and rustscan to discover open ports, services, and system information';
  }

  getRequiredPermissions(): Array<keyof EngagementScope['permissions']> {
    return ['activeScanning'];
  }

  extractTargets(params: NetworkReconParams): string[] {
    return params.targets || [];
  }

  getParameterSchema(): object {
    return {
      type: 'object',
      properties: {
        targets: {
          type: 'array',
          items: { type: 'string' },
          description: 'Target IP addresses or CIDR ranges (e.g., ["192.168.1.0/24", "10.0.0.1"])',
          minItems: 1
        },
        scanType: {
          type: 'string',
          enum: ['quick', 'full', 'custom'],
          default: 'quick',
          description: 'Type of scan to perform'
        },
        ports: {
          type: 'string',
          description: 'Specific ports to scan (e.g., "80,443,8080-8090") - required for custom scan type'
        },
        osDetection: {
          type: 'boolean',
          default: false,
          description: 'Enable OS detection (requires elevated privileges)'
        },
        serviceDetection: {
          type: 'boolean',
          default: true,
          description: 'Enable service version detection'
        },
        aggressiveTiming: {
          type: 'boolean',
          default: false,
          description: 'Use aggressive timing (faster but more detectable)'
        },
        preferredTool: {
          type: 'string',
          enum: ['nmap', 'rustscan', 'auto'],
          default: 'auto',
          description: 'Preferred scanning tool'
        },
        maxRate: {
          type: 'number',
          minimum: 1,
          maximum: 10000,
          description: 'Maximum scan rate in packets per second'
        }
      },
      required: ['targets']
    };
  }

  protected async executeImpl(params: NetworkReconParams): Promise<ToolExecutionResult> {
    try {
      // Validate scan type and ports
      if (params.scanType === 'custom' && !params.ports) {
        throw new Error('Custom scan type requires ports parameter');
      }

      // Check tool availability and choose best option
      const availableTool = await this.selectBestTool(params.preferredTool);
      
      const results: NmapResult[] = [];
      const findings: SecurityFinding[] = [];
      
      // Scan each target
      for (const target of params.targets) {
        this.context.logger('info', `Scanning target: ${target}`, { tool: availableTool });
        
        const targetResults = await this.scanTarget(target, params, availableTool);
        results.push(...targetResults);
        
        // Generate findings for interesting ports/services
        const targetFindings = this.generateFindings(targetResults);
        findings.push(...targetFindings);
      }

      // Convert results to ReconData format
      const reconData = this.convertToReconData(results);

      return {
        success: true,
        data: {
          tool: availableTool,
          scanParams: params,
          results: results
        },
        findings,
        reconData: { openPorts: reconData }
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.context.logger('error', `Network reconnaissance failed: ${errorMessage}`);
      throw error;
    }
  }

  private async selectBestTool(preferred?: string): Promise<'nmap' | 'rustscan'> {
    if (preferred && preferred !== 'auto') {
      const available = await this.checkToolAvailable(preferred as 'nmap' | 'rustscan');
      if (available) {
        return preferred as 'nmap' | 'rustscan';
      } else {
        this.context.logger('warn', `Preferred tool ${preferred} not available, falling back to auto-selection`);
      }
    }

    // Auto-select based on availability
    const rustScanAvailable = await this.checkToolAvailable('rustscan');
    const nmapAvailable = await this.checkToolAvailable('nmap');

    if (rustScanAvailable) {
      return 'rustscan';
    } else if (nmapAvailable) {
      return 'nmap';
    } else {
      throw new Error('Neither nmap nor rustscan is available. Please install one of these tools.');
    }
  }

  private async checkToolAvailable(tool: 'nmap' | 'rustscan'): Promise<boolean> {
    try {
      await execAsync(`which ${tool}`);
      return true;
    } catch {
      return false;
    }
  }

  private async scanTarget(target: string, params: NetworkReconParams, tool: 'nmap' | 'rustscan'): Promise<NmapResult[]> {
    if (tool === 'rustscan') {
      return await this.runRustScan(target, params);
    } else {
      return await this.runNmapScan(target, params);
    }
  }

  private async runNmapScan(target: string, params: NetworkReconParams): Promise<NmapResult[]> {
    const args = ['nmap', '-oX', '-']; // XML output to stdout

    // Add scan type specific arguments
    switch (params.scanType) {
      case 'quick':
        args.push('-F'); // Fast scan (top 100 ports)
        break;
      case 'full':
        args.push('-p-'); // All 65535 ports
        break;
      case 'custom':
        args.push(`-p${params.ports}`);
        break;
    }

    // Add optional features
    if (params.serviceDetection) {
      args.push('-sV');
    }
    if (params.osDetection) {
      args.push('-O');
    }
    if (params.aggressiveTiming) {
      args.push('-T4');
    } else {
      args.push('-T3'); // Normal timing
    }
    if (params.maxRate) {
      args.push(`--max-rate=${params.maxRate}`);
    }

    args.push(target);

    const command = args.join(' ');
    this.context.logger('debug', `Executing nmap command: ${command}`);

    const { stdout, stderr } = await execAsync(command, { 
      timeout: 300000, // 5 minute timeout
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });

    if (stderr) {
      this.context.logger('warn', `Nmap stderr: ${stderr}`);
    }

    return this.parseNmapXml(stdout);
  }

  private async runRustScan(target: string, params: NetworkReconParams): Promise<NmapResult[]> {
    const args = ['rustscan', '-a', target, '--greppable'];

    // RustScan is primarily for port discovery, then we use nmap for service detection
    if (params.scanType === 'quick') {
      args.push('--top');
    } else if (params.scanType === 'custom' && params.ports) {
      args.push('-p', params.ports);
    }
    // For 'full' scan, rustscan scans all ports by default

    if (params.maxRate) {
      args.push('--rate', params.maxRate.toString());
    }

    const command = args.join(' ');
    this.context.logger('debug', `Executing rustscan command: ${command}`);

    try {
      const { stdout, stderr } = await execAsync(command, { 
        timeout: 300000,
        maxBuffer: 10 * 1024 * 1024
      });

      if (stderr) {
        this.context.logger('warn', `RustScan stderr: ${stderr}`);
      }

      // Parse RustScan output and convert to our format
      const rustScanResults = this.parseRustScanOutput(stdout);

      // If service detection is requested, run nmap on discovered ports
      if (params.serviceDetection && rustScanResults.length > 0) {
        return await this.enhanceWithNmap(target, rustScanResults, params);
      }

      return rustScanResults;
    } catch (error) {
      this.context.logger('warn', `RustScan failed, falling back to nmap: ${error}`);
      return await this.runNmapScan(target, params);
    }
  }

  private parseNmapXml(xmlOutput: string): NmapResult[] {
    // For now, implement a basic XML parser
    // In production, you'd want to use a proper XML parser library
    const results: NmapResult[] = [];
    
    // Extract host and port information using regex (simplified)
    const hostRegex = /<host[^>]*>[\s\S]*?<\/host>/g;
    const hosts = xmlOutput.match(hostRegex) || [];

    for (const hostXml of hosts) {
      const ipMatch = hostXml.match(/<address addr="([^"]+)"/);
      if (!ipMatch) continue;

      const host = ipMatch[1];
      const ports: NmapResult['ports'] = [];

      const portRegex = /<port protocol="([^"]+)" portid="([^"]+)"[\s\S]*?<\/port>/g;
      let portMatch;
      
      while ((portMatch = portRegex.exec(hostXml)) !== null) {
        const protocol = portMatch[1] as 'tcp' | 'udp';
        const port = parseInt(portMatch[2]);
        
        const stateMatch = portMatch[0].match(/<state state="([^"]+)"/);
        const serviceMatch = portMatch[0].match(/<service name="([^"]+)"[^>]*>/);
        const versionMatch = portMatch[0].match(/product="([^"]+)"/);

        if (stateMatch?.[1] === 'open') {
          ports.push({
            port,
            protocol,
            state: 'open',
            service: serviceMatch?.[1] || 'unknown',
            version: versionMatch?.[1]
          });
        }
      }

      if (ports.length > 0) {
        results.push({ host, ports });
      }
    }

    return results;
  }

  private parseRustScanOutput(output: string): NmapResult[] {
    const results: NmapResult[] = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      const match = line.match(/Host: ([^\s]+).*Ports: (.+)/);
      if (match) {
        const host = match[1];
        const portsStr = match[2];
        const ports: NmapResult['ports'] = [];

        const portMatches = portsStr.split(',');
        for (const portMatch of portMatches) {
          const portInfo = portMatch.trim().split('/');
          if (portInfo.length >= 2) {
            const port = parseInt(portInfo[0]);
            const state = portInfo[1];
            const protocol = portInfo[2] || 'tcp';

            if (state === 'open') {
              ports.push({
                port,
                protocol: protocol as 'tcp' | 'udp',
                state: 'open',
                service: 'unknown'
              });
            }
          }
        }

        if (ports.length > 0) {
          results.push({ host, ports });
        }
      }
    }

    return results;
  }

  private async enhanceWithNmap(target: string, rustScanResults: NmapResult[], params: NetworkReconParams): Promise<NmapResult[]> {
    // Extract all discovered ports
    const allPorts = rustScanResults.flatMap(result => 
      result.ports.map(p => p.port)
    ).join(',');

    if (!allPorts) return rustScanResults;

    // Run nmap with service detection on discovered ports
    const nmapParams = {
      ...params,
      scanType: 'custom' as const,
      ports: allPorts
    };

    return await this.runNmapScan(target, nmapParams);
  }

  public generateFindings(results: NmapResult[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const timestamp = new Date();

    for (const result of results) {
      for (const port of result.ports) {
        // Generate findings for interesting services
        let severity: SecurityFinding['severity'] = 'info';
        let title = `Open ${port.service} service`;
        let description = `Port ${port.port}/${port.protocol} is open running ${port.service}`;

        // Classify based on service type
        if (this.isHighRiskService(port.service, port.port)) {
          severity = 'medium';
          title = `High-risk service exposed: ${port.service}`;
          description += '. This service is commonly targeted by attackers.';
        } else if (this.isAdminService(port.service, port.port)) {
          severity = 'medium';
          title = `Administrative service exposed: ${port.service}`;
          description += '. Administrative services should typically not be exposed externally.';
        }

        findings.push({
          id: `${result.host}-${port.port}-${port.protocol}`,
          severity,
          type: 'service-discovery',
          target: result.host,
          port: port.port,
          protocol: port.protocol,
          title,
          description,
          impact: this.getServiceImpact(port.service, port.port),
          remediation: this.getServiceRemediation(port.service, port.port),
          evidence: [`Port scan revealed ${port.service} on ${result.host}:${port.port}/${port.protocol}`],
          references: [],
          discoveredAt: timestamp,
          discoveredBy: this.getToolName(),
          status: 'new'
        });
      }
    }

    return findings;
  }

  public isHighRiskService(service: string, port: number): boolean {
    const highRiskServices = ['ftp', 'telnet', 'rlogin', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'];
    const highRiskPorts = [21, 23, 513, 3306, 5432, 27017, 6379, 9200];
    
    return highRiskServices.includes(service.toLowerCase()) || highRiskPorts.includes(port);
  }

  public isAdminService(service: string, port: number): boolean {
    const adminServices = ['ssh', 'rdp', 'vnc', 'snmp'];
    const adminPorts = [22, 3389, 5900, 161];
    
    return adminServices.includes(service.toLowerCase()) || adminPorts.includes(port);
  }

  private getServiceImpact(service: string, port: number): string {
    switch (service.toLowerCase()) {
      case 'ftp':
        return 'FTP services may allow unauthorized file access or credential theft';
      case 'telnet':
        return 'Telnet transmits credentials in plaintext and provides remote access';
      case 'ssh':
        return 'SSH provides administrative access if credentials are compromised';
      case 'rdp':
        return 'RDP provides full remote desktop access if credentials are compromised';
      default:
        return `Service ${service} on port ${port} increases attack surface`;
    }
  }

  private getServiceRemediation(service: string, port: number): string {
    switch (service.toLowerCase()) {
      case 'ftp':
        return 'Consider using SFTP instead of FTP, implement access controls, and ensure strong authentication';
      case 'telnet':
        return 'Replace Telnet with SSH for secure remote access';
      case 'ssh':
        return 'Ensure SSH is properly configured with key-based authentication and disable root login';
      case 'rdp':
        return 'Secure RDP with network-level authentication, strong passwords, and firewall restrictions';
      default:
        return `Review if ${service} needs to be exposed and implement appropriate access controls`;
    }
  }

  private convertToReconData(results: NmapResult[]): ReconData['openPorts'] {
    const openPorts: ReconData['openPorts'] = [];
    const timestamp = new Date();

    for (const result of results) {
      for (const port of result.ports) {
        openPorts.push({
          host: result.host,
          port: port.port,
          protocol: port.protocol,
          service: port.service,
          version: port.version,
          banner: port.banner,
          timestamp
        });
      }
    }

    return openPorts;
  }
}