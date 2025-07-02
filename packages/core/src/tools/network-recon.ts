/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, ToolResult } from './tools.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as net from 'net';
import process from 'node:process';
import { SecurityFinding, FindingTypes, FindingUtils } from '../types/security.js';
import { MemoryFindingStorage } from '../services/findingStorage.js';

const execAsync = promisify(exec);

interface NetworkReconParams {
  /** Target IP addresses or CIDR ranges */
  targets: string[];
  /** Scan type: quick, full, or custom */
  scanType?: 'quick' | 'full' | 'custom';
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

interface ScanResult {
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

// SecurityFinding interface now imported from ../types/security.js

const networkReconSchema = {
  name: 'network_recon',
  description: 'Performs network reconnaissance using nmap and rustscan to discover open ports, services, and system information. Requires proper authorization and activeScanning permission.',
  parameters: {
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
        description: 'Type of scan to perform: quick (top 100 ports), full (all ports), custom (specific ports)'
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
  }
};

const networkReconDescription = `
Performs intelligent network reconnaissance to discover open ports, services, and system information.

This tool wraps industry-standard tools like nmap and rustscan to provide:
- Port scanning and service discovery
- OS fingerprinting (with appropriate permissions)
- Service version detection
- Intelligent tool selection and fallback
- Structured output and security finding generation
- Scope validation and audit logging

**IMPORTANT SECURITY REQUIREMENTS:**
- Requires explicit authorization for target networks
- Must have proper engagement scope and permissions
- All targets should be within approved IP ranges
- Tool execution is logged for audit purposes

**Tool Dependencies:**
This tool requires either 'nmap' or 'rustscan' to be installed:
- Install nmap: \`brew install nmap\` (macOS) or \`apt-get install nmap\` (Ubuntu)
- Install rustscan: \`cargo install rustscan\` or download from GitHub releases

**Usage Examples:**
- Quick scan: \`{"targets": ["192.168.1.0/24"], "scanType": "quick"}\`
- Full port scan: \`{"targets": ["10.0.0.1"], "scanType": "full", "serviceDetection": true}\`
- Custom ports: \`{"targets": ["target.example.com"], "scanType": "custom", "ports": "80,443,8080-8090"}\`

## Parameters

- \`targets\` (array, required): Target IP addresses, hostnames, or CIDR ranges
- \`scanType\` (string): Scan scope - 'quick' (top 100 ports), 'full' (all 65535 ports), or 'custom'
- \`ports\` (string): Specific ports for custom scans (e.g., "80,443,1000-2000")
- \`serviceDetection\` (boolean): Enable service version detection (default: true)
- \`osDetection\` (boolean): Enable OS fingerprinting (requires root/admin privileges)
- \`aggressiveTiming\` (boolean): Use faster but more detectable scan timing
- \`preferredTool\` (string): Tool preference - 'nmap', 'rustscan', or 'auto'
- \`maxRate\` (number): Maximum packet rate limit for stealth considerations
`;

export class NetworkReconTool extends BaseTool<NetworkReconParams, ToolResult> {
  static readonly Name: string = networkReconSchema.name;
  private targetDir: string;

  constructor(targetDir?: string) {
    super(
      NetworkReconTool.Name,
      'Network Reconnaissance',
      networkReconDescription,
      networkReconSchema.parameters as Record<string, unknown>,
    );
    this.targetDir = targetDir || process.cwd();
  }

  async execute(params: NetworkReconParams, signal: AbortSignal): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      // Validate parameters
      if (params.scanType === 'custom' && !params.ports) {
        throw new Error('Custom scan type requires ports parameter');
      }

      // Check tool availability and choose best option
      const availableTool = await this.selectBestTool(params.preferredTool);
      
      const results: ScanResult[] = [];
      const findings: SecurityFinding[] = [];
      
      // Scan each target
      for (const target of params.targets) {
        console.log(`[INFO] NetworkRecon: Scanning target ${target} with ${availableTool}`);
        
        const targetResults = await this.scanTarget(target, params, availableTool);
        results.push(...targetResults);
        
        // Generate findings for interesting ports/services
        const targetFindings = await this.generateFindings(targetResults);
        findings.push(...targetFindings);
      }

      // Convert results to structured format
      const openPorts = this.convertToOpenPorts(results);
      const executionTime = Date.now() - startTime;

      // Format results for display
      const summary = this.formatResults({
        data: { tool: availableTool, scanParams: params },
        findings,
        reconData: { openPorts },
        metrics: { executionTime }
      });

      return {
        llmContent: JSON.stringify({
          success: true,
          tool: 'network_recon',
          summary: summary,
          findings: findings.length,
          openPorts: openPorts.length,
          executionTime,
          data: {
            scanParams: params,
            toolUsed: availableTool,
            targets: params.targets,
            results: results
          }
        }),
        returnDisplay: summary
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const executionTime = Date.now() - startTime;
      
      console.error(`[ERROR] NetworkRecon execution failed: ${errorMessage}`);
      
      return {
        llmContent: JSON.stringify({ 
          success: false, 
          error: errorMessage,
          tool: 'network_recon',
          executionTime
        }),
        returnDisplay: `❌ **Network reconnaissance failed**: ${errorMessage}\n\n💡 **Make sure you have nmap or rustscan installed:**\n  • macOS: \`brew install nmap\`\n  • Ubuntu: \`apt-get install nmap\`\n  • Rust: \`cargo install rustscan\``
      };
    }
  }

  private async selectBestTool(preferred?: string): Promise<'nmap' | 'rustscan'> {
    if (preferred && preferred !== 'auto') {
      const available = await this.checkToolAvailable(preferred as 'nmap' | 'rustscan');
      if (available) {
        return preferred as 'nmap' | 'rustscan';
      } else {
        console.warn(`[WARN] NetworkRecon: Preferred tool ${preferred} not available, falling back to auto-selection`);
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
      throw new Error('Neither nmap nor rustscan is available. Please install one of these tools:\n  • nmap: brew install nmap (macOS) or apt-get install nmap (Ubuntu)\n  • rustscan: cargo install rustscan');
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

  private async scanTarget(target: string, params: NetworkReconParams, tool: 'nmap' | 'rustscan'): Promise<ScanResult[]> {
    if (tool === 'rustscan') {
      return await this.runRustScan(target, params);
    } else {
      return await this.runNmapScan(target, params);
    }
  }

  private async runNmapScan(target: string, params: NetworkReconParams): Promise<ScanResult[]> {
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
    console.log(`[DEBUG] NetworkRecon: Executing nmap command: ${command}`);

    const { stdout, stderr } = await execAsync(command, { 
      timeout: 300000, // 5 minute timeout
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });

    if (stderr) {
      console.warn(`[WARN] NetworkRecon: Nmap stderr: ${stderr}`);
    }

    return this.parseNmapXml(stdout);
  }

  private async runRustScan(target: string, params: NetworkReconParams): Promise<ScanResult[]> {
    const args = ['rustscan', '-a', target, '--greppable'];

    // RustScan is primarily for port discovery
    if (params.scanType === 'quick') {
      args.push('--top');
    } else if (params.scanType === 'custom' && params.ports) {
      args.push('-p', params.ports);
    }

    if (params.maxRate) {
      args.push('--rate', params.maxRate.toString());
    }

    const command = args.join(' ');
    console.log(`[DEBUG] NetworkRecon: Executing rustscan command: ${command}`);

    try {
      const { stdout, stderr } = await execAsync(command, { 
        timeout: 300000,
        maxBuffer: 10 * 1024 * 1024
      });

      if (stderr) {
        console.warn(`[WARN] NetworkRecon: RustScan stderr: ${stderr}`);
      }

      // Parse RustScan output and convert to our format
      const rustScanResults = this.parseRustScanOutput(stdout);

      // If service detection is requested, run nmap on discovered ports
      if (params.serviceDetection && rustScanResults.length > 0) {
        return await this.enhanceWithNmap(target, rustScanResults, params);
      }

      return rustScanResults;
    } catch (error) {
      console.warn(`[WARN] NetworkRecon: RustScan failed, falling back to nmap: ${error}`);
      return await this.runNmapScan(target, params);
    }
  }

  private parseNmapXml(xmlOutput: string): ScanResult[] {
    const results: ScanResult[] = [];
    
    // Extract host and port information using regex (simplified XML parsing)
    const hostRegex = /<host[^>]*>[\s\S]*?<\/host>/g;
    const hosts = xmlOutput.match(hostRegex) || [];

    for (const hostXml of hosts) {
      const ipMatch = hostXml.match(/<address addr="([^"]+)"/);
      if (!ipMatch) continue;

      const host = ipMatch[1];
      const ports: ScanResult['ports'] = [];

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

  private parseRustScanOutput(output: string): ScanResult[] {
    const results: ScanResult[] = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      const match = line.match(/Host: ([^\s]+).*Ports: (.+)/);
      if (match) {
        const host = match[1];
        const portsStr = match[2];
        const ports: ScanResult['ports'] = [];

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

  private async enhanceWithNmap(target: string, rustScanResults: ScanResult[], params: NetworkReconParams): Promise<ScanResult[]> {
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

  private async generateFindings(results: ScanResult[]): Promise<SecurityFinding[]> {
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

        const finding: SecurityFinding = {
          id: FindingUtils.generateId(result.host, FindingTypes.SERVICE_DISCOVERY, port.port),
          severity,
          type: FindingTypes.SERVICE_DISCOVERY,
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
          discoveredBy: 'NetworkReconTool',
          status: 'new'
        };
        
        findings.push(finding);
        
        // Store finding in centralized storage
        try {
          const storage = MemoryFindingStorage.getInstance(this.targetDir);
          await storage.storeFinding(finding);
        } catch (error) {
          console.warn(`[WARN] NetworkRecon: Failed to store finding ${finding.id}: ${error}`);
        }
      }
    }

    return findings;
  }

  private isHighRiskService(service: string, port: number): boolean {
    const highRiskServices = ['ftp', 'telnet', 'rlogin', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'];
    const highRiskPorts = [21, 23, 513, 3306, 5432, 27017, 6379, 9200];
    
    return highRiskServices.includes(service.toLowerCase()) || highRiskPorts.includes(port);
  }

  private isAdminService(service: string, port: number): boolean {
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

  private convertToOpenPorts(results: ScanResult[]) {
    const openPorts: any[] = [];
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

  private formatResults(result: any): string {
    const { data, findings, reconData } = result;
    const openPorts = reconData?.openPorts || [];
    
    let summary = `## 🕵️ Network Reconnaissance Results\n\n`;
    summary += `**🛠️ Tool Used:** ${data?.tool || 'unknown'}\n`;
    summary += `**🎯 Targets:** ${data?.scanParams?.targets?.join(', ') || 'unknown'}\n`;
    summary += `**📡 Scan Type:** ${data?.scanParams?.scanType || 'unknown'}\n`;
    if (result.metrics?.executionTime) {
      summary += `**⏱️ Execution Time:** ${Math.round(result.metrics.executionTime / 1000)}s\n`;
    }
    summary += `\n`;

    if (openPorts.length > 0) {
      summary += `### 🔍 Discovered Services (${openPorts.length} total)\n\n`;
      
      // Group by host
      const hostGroups = openPorts.reduce((groups: any, port: any) => {
        if (!groups[port.host]) groups[port.host] = [];
        groups[port.host].push(port);
        return groups;
      }, {});

      for (const [host, ports] of Object.entries(hostGroups)) {
        summary += `**${host}:**\n`;
        (ports as any[])
          .sort((a, b) => a.port - b.port)
          .forEach(port => {
            summary += `- ${port.port}/${port.protocol}: **${port.service}**`;
            if (port.version) summary += ` (${port.version})`;
            summary += `\n`;
          });
        summary += `\n`;
      }
    } else {
      summary += `### 📭 No Open Ports Found\n\nNo open ports were discovered on the scanned targets.\n\n`;
    }

    if (findings && findings.length > 0) {
      summary += `### 🚨 Security Findings (${findings.length} total)\n\n`;
      
      // Count findings by severity
      const severityCounts = findings.reduce((counts: any, finding: any) => {
        counts[finding.severity] = (counts[finding.severity] || 0) + 1;
        return counts;
      }, {});

      // Display severity summary with emojis
      const severityEmojis = {
        critical: '🚨',
        high: '⚠️',
        medium: '⚡',
        low: '📝',
        info: 'ℹ️'
      };

      for (const [severity, count] of Object.entries(severityCounts)) {
        const emoji = (severityEmojis as any)[severity] || '📝';
        summary += `${emoji} **${severity.toUpperCase()}**: ${count}\n`;
      }
      
      // Show top 3 high-priority findings
      const highPriorityFindings = findings
        .filter((f: any) => ['critical', 'high', 'medium'].includes(f.severity))
        .slice(0, 3);

      if (highPriorityFindings.length > 0) {
        summary += `\n**🔥 Priority Findings:**\n`;
        highPriorityFindings.forEach((finding: any, i: number) => {
          const emoji = (severityEmojis as any)[finding.severity] || '📝';
          summary += `${i + 1}. ${emoji} **${finding.title}** (${finding.target}:${finding.port})\n`;
          summary += `   ${finding.impact}\n`;
        });
      }

      if (findings.length > 3) {
        summary += `\n_... and ${findings.length - 3} more findings. Use detailed analysis for complete results._\n`;
      }
    }

    summary += `\n---\n✅ **Scan completed at:** ${new Date().toLocaleString()}`;

    return summary;
  }
}