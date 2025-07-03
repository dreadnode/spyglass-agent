/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, ToolResult } from './tools.js';
import { promises as fs } from 'fs';
import path from 'path';
import process from 'node:process';
import { MemoryFindingStorage } from '../services/findingStorage.js';
import { FindingCorrelator, CorrelatedFinding } from '../services/findingCorrelation.js';
import { CvssScorer } from '../services/cvssScoring.js';
import { SecurityFinding } from '../types/security.js';

// Use SecurityFinding from types/security.js instead of local interface

interface ReportMetadata {
  title: string;
  assessmentType: 'network-scan' | 'external-recon' | 'full-assessment' | 'custom';
  scope: string[];
  assessor: string;
  startTime: Date;
  endTime?: Date;
  version: string;
}

interface ReportSection {
  title: string;
  content: string;
  findings?: SecurityFinding[];
  subsections?: ReportSection[];
}

interface SecurityReport {
  metadata: ReportMetadata;
  executiveSummary: {
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    riskRating: 'critical' | 'high' | 'medium' | 'low';
    keyRecommendations: string[];
    averageCvssScore?: number;
    highestCvssScore?: number;
    riskDistribution?: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
  };
  sections: ReportSection[];
  findings: SecurityFinding[];
  appendices?: {
    toolOutput?: string;
    rawData?: unknown;
  };
}

interface SecurityReportParams {
  /** Report title */
  title?: string;
  /** Assessment scope description */
  scope?: string[];
  /** Assessor name/organization */
  assessor?: string;
  /** Type of assessment being reported */
  assessmentType?: 'network-scan' | 'external-recon' | 'full-assessment' | 'custom';
  /** Export format(s) */
  format?: Array<'markdown' | 'json' | 'html'>;
  /** Output directory for report files */
  outputDir?: string;
  /** Include raw tool output in appendices */
  includeRawData?: boolean;
  /** Aggregate findings from memory tool */
  aggregateFromMemory?: boolean;
  /** Custom findings to include */
  customFindings?: SecurityFinding[];
}

const securityReportSchema = {
  name: 'security_report',
  description: 'Generates comprehensive security assessment reports by aggregating findings from reconnaissance tools and memory. Supports multiple export formats.',
  parameters: {
    type: 'object',
    properties: {
      title: {
        type: 'string',
        default: 'Security Assessment Report',
        description: 'Title for the security report'
      },
      scope: {
        type: 'array',
        items: { type: 'string' },
        description: 'Assessment scope (e.g., ["192.168.1.0/24", "example.com"])'
      },
      assessor: {
        type: 'string',
        description: 'Name or organization conducting the assessment'
      },
      assessmentType: {
        type: 'string',
        enum: ['network-scan', 'external-recon', 'full-assessment', 'custom'],
        default: 'full-assessment',
        description: 'Type of security assessment'
      },
      format: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['markdown', 'json', 'html']
        },
        default: ['markdown'],
        description: 'Export format(s) for the report'
      },
      outputDir: {
        type: 'string',
        default: './security-reports',
        description: 'Directory to save report files'
      },
      includeRawData: {
        type: 'boolean',
        default: false,
        description: 'Include raw tool output in appendices'
      },
      aggregateFromMemory: {
        type: 'boolean',
        default: true,
        description: 'Aggregate security findings from memory tool'
      },
      customFindings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            type: { type: 'string' },
            target: { type: 'string' },
            title: { type: 'string' },
            description: { type: 'string' },
            impact: { type: 'string' },
            remediation: { type: 'string' },
            evidence: { type: 'array', items: { type: 'string' } }
          },
          required: ['id', 'severity', 'type', 'target', 'title', 'description']
        },
        description: 'Additional custom findings to include in report'
      }
    }
  }
};

const securityReportDescription = `
Generates comprehensive security assessment reports by aggregating findings from all reconnaissance tools.

This tool provides:
- Professional security report generation with executive summaries
- Aggregation of findings from NetworkReconTool, ExternalReconTool, and memory
- Multiple export formats (Markdown, JSON, HTML) 
- Customizable report templates and sections
- Risk-based prioritization and remediation guidance
- Evidence collection and audit trails

**Report Structure:**
- Executive Summary with risk ratings and key recommendations
- Technical Findings organized by severity and category
- Detailed remediation guidance with prioritization
- Evidence and supporting data
- Optional appendices with raw tool output

**Usage Examples:**
- Generate full assessment report: \`{"title": "Penetration Test Report", "assessmentType": "full-assessment"}\`
- Network scan summary: \`{"title": "Network Security Scan", "assessmentType": "network-scan", "format": ["markdown", "json"]}\`
- Custom scope report: \`{"title": "External Assessment", "scope": ["example.com"], "assessor": "Red Team Alpha"}\`

## Parameters

- \`title\` (string): Report title and filename base
- \`scope\` (array): Target systems/networks assessed (e.g., IP ranges, domains)
- \`assessor\` (string): Name/organization conducting the assessment
- \`assessmentType\` (string): Type of assessment - 'network-scan', 'external-recon', 'full-assessment', or 'custom'
- \`format\` (array): Output formats - 'markdown', 'json', and/or 'html'
- \`outputDir\` (string): Directory for generated report files
- \`includeRawData\` (boolean): Include raw tool output in appendices
- \`aggregateFromMemory\` (boolean): Pull findings from memory tool storage
- \`customFindings\` (array): Additional findings to include manually
`;

export class SecurityReportTool extends BaseTool<SecurityReportParams, ToolResult> {
  static readonly Name: string = securityReportSchema.name;
  private targetDir: string;

  constructor(targetDir?: string) {
    super(
      SecurityReportTool.Name,
      'Security Assessment Report Generator',
      securityReportDescription,
      securityReportSchema.parameters as Record<string, unknown>,
    );
    this.targetDir = targetDir || process.cwd();
  }

  async execute(params: SecurityReportParams, signal: AbortSignal): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      console.log(`[INFO] SecurityReport: Generating report "${params.title || 'Security Assessment Report'}"`);
      
      // Aggregate findings from various sources
      const { findings, correlations, riskStats } = await this.aggregateFindings(params);
      
      // Generate report structure
      const report = await this.generateReport(params, findings, correlations, riskStats);
      
      // Export in requested formats
      const outputFiles = await this.exportReport(report, params);
      
      const executionTime = Date.now() - startTime;
      const summary = this.formatResults(report, outputFiles, executionTime);

      return {
        llmContent: JSON.stringify({
          success: true,
          tool: 'security_report',
          summary: summary,
          reportPath: outputFiles[0], // Primary output file
          formats: outputFiles.map(f => path.extname(f).slice(1)),
          totalFindings: findings.length,
          criticalFindings: findings.filter(f => f.severity === 'critical').length,
          correlationGroups: correlations.length,
          executionTime,
          data: {
            params,
            outputFiles,
            findingsCount: findings.length
          }
        }),
        returnDisplay: summary
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const executionTime = Date.now() - startTime;
      
      console.error(`[ERROR] SecurityReport execution failed: ${errorMessage}`);
      
      return {
        llmContent: JSON.stringify({ 
          success: false, 
          error: errorMessage,
          tool: 'security_report',
          executionTime
        }),
        returnDisplay: `❌ **Security report generation failed**: ${errorMessage}\n\n💡 **Check that:**\n  • Output directory is writable\n  • Required permissions are available\n  • Memory tool contains security findings`
      };
    }
  }

  private async aggregateFindings(params: SecurityReportParams): Promise<{
    findings: SecurityFinding[];
    correlations: CorrelatedFinding[];
    riskStats?: {
      averageCvssScore: number;
      highestCvssScore: number;
      findingsWithoutCvss: number;
      riskDistribution: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
    };
  }> {
    const findings: SecurityFinding[] = [];
    
    // Add custom findings if provided
    if (params.customFindings) {
      const customFindings = params.customFindings.map(f => {
        const baseFinding = {
          ...f,
          discoveredAt: new Date(),
          discoveredBy: f.discoveredBy || 'manual-entry',
          status: f.status || 'new' as const,
          evidence: f.evidence || [],
          references: f.references || []
        };
        
        // Auto-score custom findings if they don't have CVSS scores
        return !f.cvssScore ? CvssScorer.scoreFinding(baseFinding) : baseFinding;
      });
      
      findings.push(...customFindings);
    }

    // Aggregate from memory tool with correlation
    if (params.aggregateFromMemory) {
      const storage = MemoryFindingStorage.getInstance(this.targetDir);
      
      // Ensure all findings have CVSS scores
      await storage.recalculateCvssScores();
      
      const correlationResult = await storage.getCorrelatedFindings();
      const riskStats = await storage.getRiskStatistics();
      
      findings.push(...correlationResult.uniqueFindings);
      
      console.log(`[DEBUG] SecurityReport: Retrieved ${correlationResult.uniqueFindings.length} unique findings and ${correlationResult.correlatedGroups.length} correlation groups`);
      console.log(`[DEBUG] SecurityReport: Risk stats - Avg CVSS: ${riskStats.averageCvssScore}, Max CVSS: ${riskStats.highestCvssScore}`);
      
      return {
        findings: correlationResult.uniqueFindings,
        correlations: correlationResult.correlatedGroups,
        riskStats
      };
    }

    return {
      findings,
      correlations: []
    };
  }

  private async getMemoryFindings(): Promise<SecurityFinding[]> {
    try {
      const storage = MemoryFindingStorage.getInstance(this.targetDir);
      const findings = await storage.getFindings({
        sortBy: 'discoveredAt',
        sortOrder: 'desc'
      });
      console.log(`[DEBUG] SecurityReport: Retrieved ${findings.length} findings from centralized storage`);
      return findings;
    } catch (error) {
      console.warn(`[WARN] SecurityReport: Failed to retrieve findings from storage: ${error}`);
      return [];
    }
  }

  private async generateReport(params: SecurityReportParams, findings: SecurityFinding[], correlations: CorrelatedFinding[], riskStats?: {
    averageCvssScore: number;
    highestCvssScore: number;
    findingsWithoutCvss: number;
    riskDistribution: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
  }): Promise<SecurityReport> {
    const now = new Date();
    const metadata: ReportMetadata = {
      title: params.title || 'Security Assessment Report',
      assessmentType: params.assessmentType || 'full-assessment',
      scope: params.scope || ['Not specified'],
      assessor: params.assessor || 'Spyglass Agent',
      startTime: now,
      endTime: now,
      version: '1.0'
    };

    // Generate executive summary
    const executiveSummary = this.generateExecutiveSummary(findings, correlations, riskStats);
    
    // Organize findings into sections
    const sections = this.generateReportSections(findings, correlations, params.assessmentType || 'full-assessment');

    return {
      metadata,
      executiveSummary,
      sections,
      findings,
      appendices: params.includeRawData ? {
        toolOutput: 'Raw tool output would be stored here',
        rawData: { timestamp: now.toISOString() }
      } : undefined
    };
  }

  private generateExecutiveSummary(findings: SecurityFinding[], correlations: CorrelatedFinding[], riskStats?: {
    averageCvssScore: number;
    highestCvssScore: number;
    findingsWithoutCvss: number;
    riskDistribution: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
  }) {
    const totalFindings = findings.length;
    const criticalFindings = findings.filter(f => f.severity === 'critical').length;
    const highFindings = findings.filter(f => f.severity === 'high').length;
    const mediumFindings = findings.filter(f => f.severity === 'medium').length;
    
    // Determine overall risk rating
    let riskRating: 'critical' | 'high' | 'medium' | 'low';
    if (criticalFindings > 0) {
      riskRating = 'critical';
    } else if (highFindings > 0) {
      riskRating = 'high';
    } else if (mediumFindings > 0) {
      riskRating = 'medium';
    } else {
      riskRating = 'low';
    }

    // Generate key recommendations
    const keyRecommendations = this.generateKeyRecommendations(findings);
    
    // Calculate correlation statistics
    const attackChains = correlations.filter(c => c.type === 'chain').length;
    const relatedGroups = correlations.filter(c => c.type === 'related').length;

    return {
      totalFindings,
      criticalFindings,
      highFindings,
      riskRating,
      keyRecommendations,
      averageCvssScore: riskStats?.averageCvssScore,
      highestCvssScore: riskStats?.highestCvssScore,
      riskDistribution: riskStats?.riskDistribution,
      correlationStats: {
        attackChains,
        relatedGroups,
        totalCorrelations: correlations.length
      }
    };
  }

  private generateKeyRecommendations(findings: SecurityFinding[]): string[] {
    const recommendations = new Set<string>();
    
    // Add top 5 most critical remediation items
    findings
      .filter(f => ['critical', 'high'].includes(f.severity))
      .slice(0, 5)
      .forEach(f => recommendations.add(f.remediation));

    return Array.from(recommendations);
  }

  private generateReportSections(findings: SecurityFinding[], correlations: CorrelatedFinding[], assessmentType: string): ReportSection[] {
    const sections: ReportSection[] = [];

    // Group findings by severity
    const findingsBySeverity = {
      critical: findings.filter(f => f.severity === 'critical'),
      high: findings.filter(f => f.severity === 'high'),
      medium: findings.filter(f => f.severity === 'medium'),
      low: findings.filter(f => f.severity === 'low'),
      info: findings.filter(f => f.severity === 'info')
    };

    // Critical Findings section
    if (findingsBySeverity.critical.length > 0) {
      sections.push({
        title: 'Critical Findings',
        content: 'The following critical security issues require immediate attention:',
        findings: findingsBySeverity.critical
      });
    }

    // High Priority Findings section  
    if (findingsBySeverity.high.length > 0) {
      sections.push({
        title: 'High Priority Findings',
        content: 'These high-risk vulnerabilities should be addressed as soon as possible:',
        findings: findingsBySeverity.high
      });
    }

    // Medium Priority Findings section
    if (findingsBySeverity.medium.length > 0) {
      sections.push({
        title: 'Medium Priority Findings',
        content: 'These findings represent moderate security risks:',
        findings: findingsBySeverity.medium
      });
    }

    // Assessment-specific sections
    if (assessmentType === 'network-scan' || assessmentType === 'full-assessment') {
      const networkFindings = findings.filter(f => f.type.includes('network') || f.type.includes('service'));
      if (networkFindings.length > 0) {
        sections.push({
          title: 'Network Security Analysis',
          content: 'Analysis of network services and infrastructure security:',
          findings: networkFindings
        });
      }
    }

    if (assessmentType === 'external-recon' || assessmentType === 'full-assessment') {
      const externalFindings = findings.filter(f => f.type.includes('domain') || f.type.includes('dns') || f.type.includes('subdomain'));
      if (externalFindings.length > 0) {
        sections.push({
          title: 'External Attack Surface',
          content: 'Analysis of externally visible attack surface and misconfigurations:',
          findings: externalFindings
        });
      }
    }

    // Finding Correlation Analysis section
    if (correlations.length > 0) {
      sections.push({
        title: 'Finding Correlation Analysis',
        content: this.generateCorrelationAnalysis(correlations)
      });
    }

    // Recommendations section
    sections.push({
      title: 'Remediation Recommendations',
      content: this.generateRemediationGuidance(findings)
    });

    return sections;
  }
  
  private generateCorrelationAnalysis(correlations: CorrelatedFinding[]): string {
    let analysis = 'Analysis of relationships between security findings:\n\n';
    
    // Group correlations by type
    const attackChains = correlations.filter(c => c.type === 'chain');
    const relatedGroups = correlations.filter(c => c.type === 'related');
    const duplicates = correlations.filter(c => c.type === 'duplicate');
    
    if (attackChains.length > 0) {
      analysis += `**Attack Chains Identified (${attackChains.length}):**\n`;
      attackChains.forEach((chain, index) => {
        const riskScore = FindingCorrelator.calculateGroupRiskScore(chain);
        analysis += `${index + 1}. ${chain.primary.title} → ${chain.related.map(r => r.title).join(' → ')}\n`;
        analysis += `   Risk Score: ${riskScore.toFixed(1)}/10 | Confidence: ${(chain.confidence * 100).toFixed(0)}%\n`;
        analysis += `   Impact: These findings can be chained together to escalate privileges or access\n\n`;
      });
    }
    
    if (relatedGroups.length > 0) {
      analysis += `**Related Finding Groups (${relatedGroups.length}):**\n`;
      relatedGroups.forEach((group, index) => {
        const riskScore = FindingCorrelator.calculateGroupRiskScore(group);
        analysis += `${index + 1}. ${group.primary.title} + ${group.related.length} related finding(s)\n`;
        analysis += `   Risk Score: ${riskScore.toFixed(1)}/10 | Confidence: ${(group.confidence * 100).toFixed(0)}%\n`;
        analysis += `   Impact: These findings affect the same system or component\n\n`;
      });
    }
    
    if (duplicates.length > 0) {
      analysis += `**Duplicate Findings Merged (${duplicates.length}):**\n`;
      analysis += `Identified and consolidated ${duplicates.length} duplicate findings to avoid over-reporting.\n\n`;
    }
    
    analysis += '**Key Insights:**\n';
    if (attackChains.length > 0) {
      analysis += `• ${attackChains.length} attack chain(s) identified - prioritize remediation of chain components\n`;
    }
    if (relatedGroups.length > 0) {
      analysis += `• ${relatedGroups.length} related finding group(s) - coordinate remediation efforts\n`;
    }
    analysis += `• Finding correlation reduced noise by merging ${duplicates.length} duplicates\n`;
    
    return analysis;
  }

  private generateRemediationGuidance(findings: SecurityFinding[]): string {
    if (findings.length === 0) {
      return 'No security findings identified. Continue monitoring and periodic assessments.';
    }

    const priorityGroups = [
      { name: 'Immediate Action Required (Critical)', findings: findings.filter(f => f.severity === 'critical') },
      { name: 'High Priority (Complete within 30 days)', findings: findings.filter(f => f.severity === 'high') },
      { name: 'Medium Priority (Complete within 90 days)', findings: findings.filter(f => f.severity === 'medium') },
      { name: 'Low Priority (Address during next maintenance window)', findings: findings.filter(f => f.severity === 'low') }
    ];

    let guidance = 'The following remediation timeline is recommended:\n\n';
    
    priorityGroups.forEach(group => {
      if (group.findings.length > 0) {
        guidance += `**${group.name}:**\n`;
        group.findings.forEach(finding => {
          guidance += `- ${finding.title}: ${finding.remediation}\n`;
        });
        guidance += '\n';
      }
    });

    return guidance;
  }

  private async exportReport(report: SecurityReport, params: SecurityReportParams): Promise<string[]> {
    const formats = params.format || ['markdown'];
    const outputDir = params.outputDir || './security-reports';
    const baseFilename = this.sanitizeFilename(report.metadata.title);
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
    
    // Ensure output directory exists
    await fs.mkdir(outputDir, { recursive: true });
    
    const outputFiles: string[] = [];

    for (const format of formats) {
      const filename = `${baseFilename}-${timestamp}.${format}`;
      const filepath = path.join(outputDir, filename);
      
      let content: string;
      switch (format) {
        case 'markdown':
          content = this.exportMarkdown(report);
          break;
        case 'json':
          content = JSON.stringify(report, null, 2);
          break;
        case 'html':
          content = this.exportHtml(report);
          break;
        default:
          throw new Error(`Unsupported format: ${format}`);
      }
      
      await fs.writeFile(filepath, content, 'utf8');
      outputFiles.push(filepath);
      console.log(`[INFO] SecurityReport: Generated ${format.toUpperCase()} report: ${filepath}`);
    }

    return outputFiles;
  }

  private exportMarkdown(report: SecurityReport): string {
    let md = `# ${report.metadata.title}\n\n`;
    
    // Metadata section
    md += `**Assessment Type:** ${report.metadata.assessmentType}\n`;
    md += `**Scope:** ${report.metadata.scope.join(', ')}\n`;
    md += `**Assessor:** ${report.metadata.assessor}\n`;
    md += `**Date:** ${report.metadata.startTime.toISOString().split('T')[0]}\n`;
    md += `**Report Version:** ${report.metadata.version}\n\n`;

    // Executive Summary
    md += `## Executive Summary\n\n`;
    md += `**Overall Risk Rating:** ${report.executiveSummary.riskRating.toUpperCase()}\n\n`;
    md += `**Findings Summary:**\n`;
    md += `- Total Findings: ${report.executiveSummary.totalFindings}\n`;
    md += `- Critical: ${report.executiveSummary.criticalFindings}\n`;
    md += `- High: ${report.executiveSummary.highFindings}\n`;
    
    if (report.executiveSummary.averageCvssScore !== undefined) {
      md += `- Average CVSS Score: ${report.executiveSummary.averageCvssScore}\n`;
      md += `- Highest CVSS Score: ${report.executiveSummary.highestCvssScore}\n`;
    }
    md += '\n';
    
    if (report.executiveSummary.keyRecommendations.length > 0) {
      md += `**Key Recommendations:**\n`;
      report.executiveSummary.keyRecommendations.forEach(rec => {
        md += `- ${rec}\n`;
      });
      md += '\n';
    }

    // Report sections
    report.sections.forEach(section => {
      md += `## ${section.title}\n\n`;
      md += `${section.content}\n\n`;
      
      if (section.findings && section.findings.length > 0) {
        section.findings.forEach((finding, index) => {
          md += `### ${index + 1}. ${finding.title}\n\n`;
          md += `**Severity:** ${finding.severity.toUpperCase()}\n`;
          md += `**Target:** ${finding.target}\n`;
          md += `**Type:** ${finding.type}\n`;
          if (finding.cvssScore !== undefined) {
            md += `**CVSS Score:** ${finding.cvssScore}/10\n`;
          }
          if (finding.cvssVector) {
            md += `**CVSS Vector:** ${finding.cvssVector}\n`;
          }
          md += '\n';
          md += `**Description:** ${finding.description}\n\n`;
          md += `**Impact:** ${finding.impact}\n\n`;
          md += `**Remediation:** ${finding.remediation}\n\n`;
          
          if (finding.evidence.length > 0) {
            md += `**Evidence:**\n`;
            finding.evidence.forEach(evidence => {
              md += `- ${evidence}\n`;
            });
            md += '\n';
          }
          
          if (finding.references.length > 0) {
            md += `**References:**\n`;
            finding.references.forEach(ref => {
              md += `- ${ref}\n`;
            });
            md += '\n';
          }
          
          md += '---\n\n';
        });
      }
    });

    return md;
  }

  private exportHtml(report: SecurityReport): string {
    const css = `
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
      </style>
    `;

    let html = `<!DOCTYPE html><html><head><title>${report.metadata.title}</title>${css}</head><body>`;
    html += `<h1>${report.metadata.title}</h1>`;
    
    // Metadata
    html += `<div class="metadata">`;
    html += `<p><strong>Assessment Type:</strong> ${report.metadata.assessmentType}</p>`;
    html += `<p><strong>Scope:</strong> ${report.metadata.scope.join(', ')}</p>`;
    html += `<p><strong>Assessor:</strong> ${report.metadata.assessor}</p>`;
    html += `<p><strong>Date:</strong> ${report.metadata.startTime.toISOString().split('T')[0]}</p>`;
    html += `</div>`;

    // Executive Summary
    html += `<h2>Executive Summary</h2>`;
    html += `<p><strong>Overall Risk Rating:</strong> <span class="severity-${report.executiveSummary.riskRating}">${report.executiveSummary.riskRating.toUpperCase()}</span></p>`;
    html += `<p><strong>Total Findings:</strong> ${report.executiveSummary.totalFindings}</p>`;

    // Sections with findings
    report.sections.forEach(section => {
      html += `<h2>${section.title}</h2>`;
      html += `<p>${section.content}</p>`;
      
      if (section.findings) {
        section.findings.forEach((finding, index) => {
          html += `<div class="finding">`;
          html += `<h3>${index + 1}. ${finding.title}</h3>`;
          html += `<p><strong>Severity:</strong> <span class="severity-${finding.severity}">${finding.severity.toUpperCase()}</span></p>`;
          html += `<p><strong>Target:</strong> ${finding.target}</p>`;
          html += `<p><strong>Description:</strong> ${finding.description}</p>`;
          html += `<p><strong>Impact:</strong> ${finding.impact}</p>`;
          html += `<p><strong>Remediation:</strong> ${finding.remediation}</p>`;
          html += `</div>`;
        });
      }
    });

    html += `</body></html>`;
    return html;
  }

  private sanitizeFilename(filename: string): string {
    return filename
      .replace(/[^a-z0-9]/gi, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '')
      .toLowerCase();
  }

  private formatResults(report: SecurityReport, outputFiles: string[], executionTime: number): string {
    let summary = `## 📋 Security Report Generated\n\n`;
    summary += `**📑 Report:** ${report.metadata.title}\n`;
    summary += `**🎯 Assessment Type:** ${report.metadata.assessmentType}\n`;
    summary += `**📊 Total Findings:** ${report.findings.length}\n`;
    
    if (report.executiveSummary.criticalFindings > 0) {
      summary += `**🚨 Critical:** ${report.executiveSummary.criticalFindings}\n`;
    }
    if (report.executiveSummary.highFindings > 0) {
      summary += `**⚠️ High:** ${report.executiveSummary.highFindings}\n`;
    }
    
    summary += `**⏱️ Generation Time:** ${Math.round(executionTime / 1000)}s\n\n`;

    summary += `### 📁 Generated Files\n\n`;
    outputFiles.forEach(file => {
      const format = path.extname(file).slice(1).toUpperCase();
      summary += `- **${format}:** \`${file}\`\n`;
    });

    if (report.findings.length > 0) {
      summary += `\n### 🔍 Risk Summary\n\n`;
      summary += `**Overall Risk:** ${report.executiveSummary.riskRating.toUpperCase()}\n\n`;
      
      if (report.executiveSummary.keyRecommendations.length > 0) {
        summary += `**Top Recommendations:**\n`;
        report.executiveSummary.keyRecommendations.slice(0, 3).forEach((rec, i) => {
          summary += `${i + 1}. ${rec}\n`;
        });
      }
    } else {
      summary += `\n### ✅ No Security Issues Found\n\nNo security findings were identified during the assessment.`;
    }

    summary += `\n\n---\n📋 **Report completed at:** ${new Date().toLocaleString()}`;

    return summary;
  }
}