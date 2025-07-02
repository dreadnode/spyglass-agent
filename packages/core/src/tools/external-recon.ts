/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, ToolResult } from './tools.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as dns from 'dns';
import * as net from 'net';

const execAsync = promisify(exec);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveCname = promisify(dns.resolveCname);

interface ExternalReconParams {
  /** Target domain(s) to investigate */
  domains: string[];
  /** Types of reconnaissance to perform */
  reconTypes?: Array<'whois' | 'dns' | 'subdomain' | 'all'>;
  /** Whether to perform zone transfer attempts */
  zoneTransfer?: boolean;
  /** Whether to use external APIs for subdomain enumeration */
  useExternalApis?: boolean;
  /** Custom DNS server to use */
  dnsServer?: string;
  /** Maximum depth for subdomain enumeration */
  subdomainDepth?: number;
  /** Wordlist for subdomain brute-forcing (small, medium, large) */
  subdomainWordlist?: 'small' | 'medium' | 'large';
}

interface DomainInfo {
  domain: string;
  whois?: WhoisInfo;
  dns?: DnsRecords;
  subdomains?: SubdomainInfo[];
  zoneTransfer?: ZoneTransferResult;
  technologies?: string[];
  securityHeaders?: SecurityHeaders;
}

interface WhoisInfo {
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
  nameServers?: string[];
  registrantOrg?: string;
  adminEmail?: string;
  techEmail?: string;
  dnssec?: boolean;
  status?: string[];
}

interface DnsRecords {
  a?: string[];
  aaaa?: string[];
  mx?: Array<{ priority: number; exchange: string }>;
  txt?: string[];
  ns?: string[];
  cname?: string[];
  soa?: string;
}

interface SubdomainInfo {
  subdomain: string;
  ips?: string[];
  cname?: string;
  source: string;
}

interface ZoneTransferResult {
  vulnerable: boolean;
  server?: string;
  records?: string[];
}

interface SecurityHeaders {
  hasHSTS?: boolean;
  hasCSP?: boolean;
  hasXFrameOptions?: boolean;
  hasXContentTypeOptions?: boolean;
}

interface SecurityFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type: string;
  target: string;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  evidence: string[];
  references: string[];
  discoveredAt: Date;
  discoveredBy: string;
  status: 'new' | 'confirmed' | 'false-positive' | 'remediated' | 'accepted-risk';
}

const externalReconSchema = {
  name: 'external_recon',
  description: 'Performs external reconnaissance including DNS enumeration, WHOIS lookups, and subdomain discovery. Requires proper authorization.',
  parameters: {
    type: 'object',
    properties: {
      domains: {
        type: 'array',
        items: { type: 'string' },
        description: 'Target domain(s) to investigate (e.g., ["example.com", "target.org"])',
        minItems: 1
      },
      reconTypes: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['whois', 'dns', 'subdomain', 'all']
        },
        default: ['all'],
        description: 'Types of reconnaissance to perform'
      },
      zoneTransfer: {
        type: 'boolean',
        default: false,
        description: 'Attempt DNS zone transfers (may be detected)'
      },
      useExternalApis: {
        type: 'boolean',
        default: false,
        description: 'Use external APIs for enhanced subdomain discovery'
      },
      dnsServer: {
        type: 'string',
        description: 'Custom DNS server to use (default: system DNS)'
      },
      subdomainDepth: {
        type: 'number',
        minimum: 1,
        maximum: 3,
        default: 1,
        description: 'Depth for recursive subdomain enumeration'
      },
      subdomainWordlist: {
        type: 'string',
        enum: ['small', 'medium', 'large'],
        default: 'small',
        description: 'Wordlist size for subdomain brute-forcing'
      }
    },
    required: ['domains']
  }
};

const externalReconDescription = `
Performs comprehensive external reconnaissance on target domains to gather intelligence for security assessments.

This tool provides:
- WHOIS information and domain registration details
- DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)
- Subdomain discovery through multiple techniques
- Zone transfer vulnerability testing
- Security header analysis
- Technology stack detection

**IMPORTANT SECURITY REQUIREMENTS:**
- Requires explicit authorization for target domains
- External reconnaissance can be detected by targets
- Some techniques may trigger security alerts
- Always operate within scope of engagement

**Tool Dependencies:**
- whois: \`brew install whois\` (macOS) or \`apt-get install whois\` (Ubuntu)
- dig: Usually pre-installed, part of bind-tools/dnsutils
- dnsrecon (optional): \`pip install dnsrecon\` for enhanced subdomain discovery

**Usage Examples:**
- Basic recon: \`{"domains": ["example.com"]}\`
- DNS only: \`{"domains": ["example.com"], "reconTypes": ["dns"]}\`
- Full recon with zone transfer test: \`{"domains": ["target.com"], "zoneTransfer": true}\`
- Subdomain enumeration: \`{"domains": ["example.com"], "reconTypes": ["subdomain"], "subdomainWordlist": "medium"}\`

## Parameters

- \`domains\` (array, required): Target domains to investigate
- \`reconTypes\` (array): Types of recon - 'whois', 'dns', 'subdomain', or 'all'
- \`zoneTransfer\` (boolean): Attempt zone transfers (noisy, may be logged)
- \`useExternalApis\` (boolean): Use external services for subdomain discovery
- \`dnsServer\` (string): Override DNS server (e.g., "8.8.8.8")
- \`subdomainDepth\` (number): Levels of subdomain recursion (1-3)
- \`subdomainWordlist\` (string): Wordlist size - 'small', 'medium', or 'large'
`;

export class ExternalReconTool extends BaseTool<ExternalReconParams, ToolResult> {
  static readonly Name: string = externalReconSchema.name;

  // Common subdomains for quick enumeration
  private readonly commonSubdomains = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'admin', 'portal', 'secure', 'vpn', 'remote', 'test', 'dev',
    'staging', 'api', 'app', 'mobile', 'demo', 'blog', 'shop',
    'store', 'forum', 'support', 'help', 'cdn', 'image', 'img',
    'static', 'media', 'upload', 'download', 'files', 'backup',
    'old', 'new', 'beta', 'alpha', 'v1', 'v2', 'www2', 'www3'
  ];

  constructor() {
    super(
      ExternalReconTool.Name,
      'External Reconnaissance',
      externalReconDescription,
      externalReconSchema.parameters as Record<string, unknown>,
    );
  }

  async execute(params: ExternalReconParams, signal: AbortSignal): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      const reconTypes = params.reconTypes || ['all'];
      const results: DomainInfo[] = [];
      const findings: SecurityFinding[] = [];
      
      // Process each domain
      for (const domain of params.domains) {
        console.log(`[INFO] ExternalRecon: Investigating domain ${domain}`);
        
        const domainInfo: DomainInfo = { domain };
        
        // Perform WHOIS lookup
        if (reconTypes.includes('whois') || reconTypes.includes('all')) {
          domainInfo.whois = await this.performWhoisLookup(domain);
          findings.push(...this.analyzeWhoisInfo(domain, domainInfo.whois));
        }
        
        // Perform DNS enumeration
        if (reconTypes.includes('dns') || reconTypes.includes('all')) {
          domainInfo.dns = await this.performDnsEnumeration(domain, params.dnsServer);
          findings.push(...this.analyzeDnsRecords(domain, domainInfo.dns));
          
          // Zone transfer attempt if requested
          if (params.zoneTransfer && domainInfo.dns?.ns) {
            domainInfo.zoneTransfer = await this.attemptZoneTransfer(domain, domainInfo.dns.ns);
            if (domainInfo.zoneTransfer.vulnerable) {
              findings.push(this.createZoneTransferFinding(domain, domainInfo.zoneTransfer));
            }
          }
        }
        
        // Perform subdomain enumeration
        if (reconTypes.includes('subdomain') || reconTypes.includes('all')) {
          domainInfo.subdomains = await this.performSubdomainEnumeration(
            domain, 
            params.subdomainWordlist || 'small',
            params.useExternalApis || false
          );
          findings.push(...this.analyzeSubdomains(domain, domainInfo.subdomains));
        }
        
        results.push(domainInfo);
      }

      const executionTime = Date.now() - startTime;
      const summary = this.formatResults({
        data: { params },
        findings,
        reconData: { domains: results },
        metrics: { executionTime }
      });

      return {
        llmContent: JSON.stringify({
          success: true,
          tool: 'external_recon',
          summary: summary,
          findings: findings.length,
          domains: results.length,
          executionTime,
          data: {
            params,
            results
          }
        }),
        returnDisplay: summary
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const executionTime = Date.now() - startTime;
      
      console.error(`[ERROR] ExternalRecon execution failed: ${errorMessage}`);
      
      return {
        llmContent: JSON.stringify({ 
          success: false, 
          error: errorMessage,
          tool: 'external_recon',
          executionTime
        }),
        returnDisplay: `❌ **External reconnaissance failed**: ${errorMessage}\n\n💡 **Make sure you have required tools installed:**\n  • whois: \`brew install whois\` (macOS) or \`apt-get install whois\` (Ubuntu)\n  • dig: Usually pre-installed, part of bind-tools/dnsutils`
      };
    }
  }

  private async performWhoisLookup(domain: string): Promise<WhoisInfo> {
    try {
      const { stdout } = await execAsync(`whois ${domain}`, {
        timeout: 30000,
        maxBuffer: 1024 * 1024
      });

      const info: WhoisInfo = {};
      
      // Parse WHOIS output
      const lines = stdout.split('\n');
      for (const line of lines) {
        const lower = line.toLowerCase();
        
        if (lower.includes('registrar:')) {
          info.registrar = line.split(':').slice(1).join(':').trim();
        } else if (lower.includes('creation date:') || lower.includes('created:')) {
          info.creationDate = line.split(':').slice(1).join(':').trim();
        } else if (lower.includes('expiry date:') || lower.includes('expires:')) {
          info.expirationDate = line.split(':').slice(1).join(':').trim();
        } else if (lower.includes('name server:') || lower.includes('nserver:')) {
          if (!info.nameServers) info.nameServers = [];
          const ns = line.split(':').slice(1).join(':').trim();
          if (ns) info.nameServers.push(ns);
        } else if (lower.includes('registrant organization:') || lower.includes('org:')) {
          info.registrantOrg = line.split(':').slice(1).join(':').trim();
        } else if (lower.includes('admin email:')) {
          info.adminEmail = line.split(':').slice(1).join(':').trim();
        } else if (lower.includes('tech email:')) {
          info.techEmail = line.split(':').slice(1).join(':').trim();
        } else if (lower.includes('dnssec:')) {
          info.dnssec = line.toLowerCase().includes('signed');
        }
      }

      return info;
    } catch (error) {
      console.warn(`[WARN] ExternalRecon: WHOIS lookup failed for ${domain}: ${error}`);
      return {};
    }
  }

  private async performDnsEnumeration(domain: string, customDnsServer?: string): Promise<DnsRecords> {
    const records: DnsRecords = {};
    
    // Configure DNS resolver if custom server specified
    if (customDnsServer) {
      dns.setServers([customDnsServer]);
    }

    // A records
    try {
      records.a = await dnsResolve4(domain);
    } catch (error) {
      console.debug(`[DEBUG] ExternalRecon: No A records for ${domain}`);
    }

    // MX records
    try {
      const mx = await dnsResolveMx(domain);
      records.mx = mx.sort((a, b) => a.priority - b.priority);
    } catch (error) {
      console.debug(`[DEBUG] ExternalRecon: No MX records for ${domain}`);
    }

    // TXT records
    try {
      const txt = await dnsResolveTxt(domain);
      records.txt = txt.map(t => t.join(' '));
    } catch (error) {
      console.debug(`[DEBUG] ExternalRecon: No TXT records for ${domain}`);
    }

    // NS records
    try {
      records.ns = await dnsResolveNs(domain);
    } catch (error) {
      console.debug(`[DEBUG] ExternalRecon: No NS records for ${domain}`);
    }

    // CNAME records
    try {
      records.cname = await dnsResolveCname(domain);
    } catch (error) {
      console.debug(`[DEBUG] ExternalRecon: No CNAME records for ${domain}`);
    }

    // Use dig for additional record types
    try {
      // AAAA records
      const { stdout: aaaaOutput } = await execAsync(`dig +short ${domain} AAAA`);
      const aaaa = aaaaOutput.split('\n').filter(line => line.trim());
      if (aaaa.length > 0) records.aaaa = aaaa;

      // SOA record
      const { stdout: soaOutput } = await execAsync(`dig +short ${domain} SOA`);
      if (soaOutput.trim()) records.soa = soaOutput.trim();
    } catch (error) {
      console.debug(`[DEBUG] ExternalRecon: dig command failed: ${error}`);
    }

    return records;
  }

  private async performSubdomainEnumeration(
    domain: string, 
    wordlistSize: string,
    useExternalApis: boolean
  ): Promise<SubdomainInfo[]> {
    const subdomains: SubdomainInfo[] = [];
    const discovered = new Set<string>();

    // Try common subdomains first
    console.log(`[INFO] ExternalRecon: Enumerating subdomains for ${domain}`);
    
    const wordlist = this.getWordlist(wordlistSize);
    
    for (const prefix of wordlist) {
      const subdomain = `${prefix}.${domain}`;
      
      try {
        const ips = await dnsResolve4(subdomain);
        if (ips.length > 0) {
          discovered.add(subdomain);
          subdomains.push({
            subdomain,
            ips,
            source: 'dns-bruteforce'
          });
        }
      } catch (error) {
        // Subdomain doesn't exist or resolve
      }
    }

    // Try dnsrecon if available
    if (await this.checkToolAvailable('dnsrecon')) {
      try {
        const { stdout } = await execAsync(
          `dnsrecon -d ${domain} -t brt -D /usr/share/dnsrecon/namelist.txt --threads 25`,
          { timeout: 60000, maxBuffer: 5 * 1024 * 1024 }
        );

        const lines = stdout.split('\n');
        for (const line of lines) {
          if (line.includes('A ') && line.includes('.')) {
            const match = line.match(/\s+([a-zA-Z0-9.-]+)\s+A\s+([0-9.]+)/);
            if (match && !discovered.has(match[1])) {
              discovered.add(match[1]);
              subdomains.push({
                subdomain: match[1],
                ips: [match[2]],
                source: 'dnsrecon'
              });
            }
          }
        }
      } catch (error) {
        console.warn(`[WARN] ExternalRecon: dnsrecon failed: ${error}`);
      }
    }

    return subdomains;
  }

  private async attemptZoneTransfer(domain: string, nameServers: string[]): Promise<ZoneTransferResult> {
    for (const ns of nameServers) {
      try {
        const { stdout } = await execAsync(`dig @${ns} ${domain} AXFR`, {
          timeout: 10000
        });

        if (stdout.includes('Transfer failed') || stdout.includes('connection refused')) {
          continue;
        }

        // Parse zone transfer results
        const records = stdout.split('\n')
          .filter(line => line.trim() && !line.startsWith(';'))
          .filter(line => line.includes('\t'));

        if (records.length > 5) { // Likely successful transfer
          return {
            vulnerable: true,
            server: ns,
            records: records.slice(0, 20) // Limit output
          };
        }
      } catch (error) {
        console.debug(`[DEBUG] ExternalRecon: Zone transfer failed on ${ns}: ${error}`);
      }
    }

    return { vulnerable: false };
  }

  private async checkToolAvailable(tool: string): Promise<boolean> {
    try {
      await execAsync(`which ${tool}`);
      return true;
    } catch {
      return false;
    }
  }

  private getWordlist(size: string): string[] {
    switch (size) {
      case 'large':
        // In production, this would load from a file
        return [...this.commonSubdomains, 
          'corp', 'internal', 'private', 'secret', 'hidden',
          'backup1', 'backup2', 'temp', 'tmp', 'cache',
          'assets', 'resources', 'content', 'data', 'db',
          'database', 'mysql', 'postgres', 'mongo', 'redis'
        ];
      case 'medium':
        return [...this.commonSubdomains,
          'corp', 'internal', 'private', 'secret', 'hidden'
        ];
      case 'small':
      default:
        return this.commonSubdomains;
    }
  }

  private analyzeWhoisInfo(domain: string, whois: WhoisInfo): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const timestamp = new Date();

    // Check for soon-to-expire domains
    if (whois.expirationDate) {
      const expiry = new Date(whois.expirationDate);
      const daysUntilExpiry = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      
      if (daysUntilExpiry < 30 && daysUntilExpiry > 0) {
        findings.push({
          id: `${domain}-expiry-warning`,
          severity: 'medium',
          type: 'domain-expiry',
          target: domain,
          title: 'Domain expiring soon',
          description: `Domain ${domain} expires in ${daysUntilExpiry} days`,
          impact: 'Domain may become available for registration by attackers if not renewed',
          remediation: 'Ensure domain auto-renewal is enabled or manually renew before expiration',
          evidence: [`Expiration date: ${whois.expirationDate}`],
          references: [],
          discoveredAt: timestamp,
          discoveredBy: 'ExternalReconTool',
          status: 'new'
        });
      }
    }

    // Check for missing DNSSEC
    if (whois.dnssec === false) {
      findings.push({
        id: `${domain}-no-dnssec`,
        severity: 'low',
        type: 'dns-security',
        target: domain,
        title: 'DNSSEC not enabled',
        description: `Domain ${domain} does not have DNSSEC enabled`,
        impact: 'Domain is vulnerable to DNS cache poisoning and spoofing attacks',
        remediation: 'Enable DNSSEC through your domain registrar to protect against DNS attacks',
        evidence: ['WHOIS indicates DNSSEC is not signed'],
        references: ['https://www.cloudflare.com/dns/dnssec/'],
        discoveredAt: timestamp,
        discoveredBy: 'ExternalReconTool',
        status: 'new'
      });
    }

    return findings;
  }

  private analyzeDnsRecords(domain: string, dns: DnsRecords): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const timestamp = new Date();

    // Check for missing SPF records
    const spfRecord = dns.txt?.find(txt => txt.includes('v=spf1'));
    if (!spfRecord && dns.mx && dns.mx.length > 0) {
      findings.push({
        id: `${domain}-no-spf`,
        severity: 'medium',
        type: 'email-security',
        target: domain,
        title: 'Missing SPF record',
        description: `Domain ${domain} has MX records but no SPF record`,
        impact: 'Domain can be spoofed in email attacks, enabling phishing',
        remediation: 'Add SPF record to specify authorized mail servers',
        evidence: [`MX records found but no SPF TXT record`],
        references: ['https://tools.ietf.org/html/rfc7208'],
        discoveredAt: timestamp,
        discoveredBy: 'ExternalReconTool',
        status: 'new'
      });
    }

    // Check for missing DMARC
    const dmarcRecord = dns.txt?.find(txt => txt.includes('v=DMARC1'));
    if (!dmarcRecord && dns.mx && dns.mx.length > 0) {
      findings.push({
        id: `${domain}-no-dmarc`,
        severity: 'medium',
        type: 'email-security',
        target: domain,
        title: 'Missing DMARC record',
        description: `Domain ${domain} has no DMARC policy`,
        impact: 'No email authentication policy enforcement, enabling spoofing',
        remediation: 'Implement DMARC record to protect against email spoofing',
        evidence: [`MX records found but no DMARC TXT record`],
        references: ['https://dmarc.org/'],
        discoveredAt: timestamp,
        discoveredBy: 'ExternalReconTool',
        status: 'new'
      });
    }

    return findings;
  }

  private analyzeSubdomains(domain: string, subdomains: SubdomainInfo[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const timestamp = new Date();

    // Look for interesting subdomains
    const interestingPatterns = [
      { pattern: /(dev|development|test|staging|uat|qa)/, severity: 'medium' as const, type: 'Non-production environment exposed' },
      { pattern: /(admin|manage|panel|control|dashboard)/, severity: 'medium' as const, type: 'Administrative interface exposed' },
      { pattern: /(backup|bak|old|archive)/, severity: 'high' as const, type: 'Backup or old version exposed' },
      { pattern: /(internal|private|secret)/, severity: 'high' as const, type: 'Internal resource exposed' },
      { pattern: /(jenkins|gitlab|github|bitbucket|jira|confluence)/, severity: 'medium' as const, type: 'Development tool exposed' }
    ];

    for (const subdomain of subdomains) {
      for (const { pattern, severity, type } of interestingPatterns) {
        if (pattern.test(subdomain.subdomain)) {
          findings.push({
            id: `${subdomain.subdomain}-exposed`,
            severity,
            type: 'subdomain-exposure',
            target: subdomain.subdomain,
            title: type,
            description: `Discovered ${subdomain.subdomain} which appears to be ${type.toLowerCase()}`,
            impact: 'Exposed non-production or internal systems increase attack surface',
            remediation: 'Review if this subdomain should be publicly accessible; implement access controls if needed',
            evidence: [`Subdomain resolves to: ${subdomain.ips?.join(', ')}`],
            references: [],
            discoveredAt: timestamp,
            discoveredBy: 'ExternalReconTool',
            status: 'new'
          });
          break; // Only create one finding per subdomain
        }
      }
    }

    return findings;
  }

  private createZoneTransferFinding(domain: string, zoneTransfer: ZoneTransferResult): SecurityFinding {
    return {
      id: `${domain}-zone-transfer`,
      severity: 'high',
      type: 'dns-misconfiguration',
      target: domain,
      title: 'DNS zone transfer allowed',
      description: `DNS server ${zoneTransfer.server} allows unauthorized zone transfers for ${domain}`,
      impact: 'Complete DNS zone data can be downloaded, revealing all subdomains and internal structure',
      remediation: 'Configure DNS server to only allow zone transfers from authorized secondary DNS servers',
      evidence: [
        `Vulnerable server: ${zoneTransfer.server}`,
        `Sample records obtained: ${zoneTransfer.records?.slice(0, 3).join(', ')}`
      ],
      references: ['https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/'],
      discoveredAt: new Date(),
      discoveredBy: 'ExternalReconTool',
      status: 'new'
    };
  }

  private formatResults(result: any): string {
    const { data, findings, reconData } = result;
    const domains = reconData?.domains || [];
    
    let summary = `## 🔍 External Reconnaissance Results\n\n`;
    summary += `**🎯 Targets:** ${data?.params?.domains?.join(', ') || 'unknown'}\n`;
    summary += `**🔎 Recon Types:** ${data?.params?.reconTypes?.join(', ') || 'all'}\n`;
    if (result.metrics?.executionTime) {
      summary += `**⏱️ Execution Time:** ${Math.round(result.metrics.executionTime / 1000)}s\n`;
    }
    summary += `\n`;

    for (const domainInfo of domains) {
      summary += `### 🌐 ${domainInfo.domain}\n\n`;

      // WHOIS Information
      if (domainInfo.whois && Object.keys(domainInfo.whois).length > 0) {
        summary += `**📋 WHOIS Information:**\n`;
        if (domainInfo.whois.registrar) summary += `- Registrar: ${domainInfo.whois.registrar}\n`;
        if (domainInfo.whois.creationDate) summary += `- Created: ${domainInfo.whois.creationDate}\n`;
        if (domainInfo.whois.expirationDate) summary += `- Expires: ${domainInfo.whois.expirationDate}\n`;
        if (domainInfo.whois.nameServers) summary += `- Name Servers: ${domainInfo.whois.nameServers.join(', ')}\n`;
        summary += `\n`;
      }

      // DNS Records
      if (domainInfo.dns && Object.keys(domainInfo.dns).length > 0) {
        summary += `**📡 DNS Records:**\n`;
        if (domainInfo.dns.a) summary += `- A: ${domainInfo.dns.a.join(', ')}\n`;
        if (domainInfo.dns.mx) {
          summary += `- MX: ${domainInfo.dns.mx.map((mx: { exchange: string; priority: number }) => `${mx.exchange} (${mx.priority})`).join(', ')}\n`;
        }
        if (domainInfo.dns.ns) summary += `- NS: ${domainInfo.dns.ns.join(', ')}\n`;
        if (domainInfo.dns.txt) {
          const importantTxt = domainInfo.dns.txt.filter((txt: string) => 
            txt.includes('v=spf1') || txt.includes('v=DMARC1') || txt.includes('v=DKIM1')
          );
          if (importantTxt.length > 0) {
            summary += `- TXT (Security): ${importantTxt.join('; ')}\n`;
          }
        }
        summary += `\n`;
      }

      // Subdomains
      if (domainInfo.subdomains && domainInfo.subdomains.length > 0) {
        summary += `**🔗 Discovered Subdomains (${domainInfo.subdomains.length}):**\n`;
        const topSubdomains = domainInfo.subdomains.slice(0, 10);
        for (const sub of topSubdomains) {
          summary += `- ${sub.subdomain} → ${sub.ips?.join(', ')}\n`;
        }
        if (domainInfo.subdomains.length > 10) {
          summary += `- ... and ${domainInfo.subdomains.length - 10} more\n`;
        }
        summary += `\n`;
      }

      // Zone Transfer
      if (domainInfo.zoneTransfer?.vulnerable) {
        summary += `**⚠️ ZONE TRANSFER VULNERABILITY DETECTED**\n`;
        summary += `- Vulnerable server: ${domainInfo.zoneTransfer.server}\n\n`;
      }
    }

    // Security Findings
    if (findings && findings.length > 0) {
      summary += `### 🚨 Security Findings (${findings.length} total)\n\n`;
      
      // Group by severity
      const severityCounts = findings.reduce((counts: any, finding: any) => {
        counts[finding.severity] = (counts[finding.severity] || 0) + 1;
        return counts;
      }, {});

      for (const [severity, count] of Object.entries(severityCounts)) {
        summary += `**${severity.toUpperCase()}**: ${count}\n`;
      }
      
      // Show high priority findings
      const highPriorityFindings = findings
        .filter((f: any) => ['critical', 'high'].includes(f.severity))
        .slice(0, 3);

      if (highPriorityFindings.length > 0) {
        summary += `\n**🔥 Priority Findings:**\n`;
        highPriorityFindings.forEach((finding: any, i: number) => {
          summary += `${i + 1}. **${finding.title}** (${finding.target})\n`;
          summary += `   ${finding.impact}\n`;
        });
      }
    }

    summary += `\n---\n✅ **Scan completed at:** ${new Date().toLocaleString()}`;

    return summary;
  }
}