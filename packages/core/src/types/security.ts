/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Standardized security finding structure used across all security tools
 */
export interface SecurityFinding {
  /** Unique identifier for the finding */
  id: string;
  
  /** Severity level following CVSS-style classification */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  
  /** Type/category of the finding (e.g., 'service-discovery', 'dns-misconfiguration') */
  type: string;
  
  /** Target system, IP, domain, or resource */
  target: string;
  
  /** Optional port number for network-related findings */
  port?: number;
  
  /** Optional protocol (tcp, udp, http, etc.) */
  protocol?: string;
  
  /** Short title/summary of the finding */
  title: string;
  
  /** Detailed description of the finding */
  description: string;
  
  /** Business/security impact description */
  impact: string;
  
  /** Recommended remediation steps */
  remediation: string;
  
  /** Array of evidence supporting the finding */
  evidence: string[];
  
  /** Array of references (CVE, CWE, documentation links) */
  references: string[];
  
  /** When the finding was discovered */
  discoveredAt: Date;
  
  /** Tool or method that discovered the finding */
  discoveredBy: string;
  
  /** Current status of the finding */
  status: 'new' | 'confirmed' | 'false-positive' | 'remediated' | 'accepted-risk';
  
  /** Optional CVSS score (0.0 - 10.0) */
  cvssScore?: number;
  
  /** Optional CVSS vector string */
  cvssVector?: string;
  
  /** Optional metadata for tool-specific information */
  metadata?: Record<string, unknown>;
}

/**
 * Severity levels with numeric values for sorting and comparison
 */
export const SeverityLevels = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
} as const;

/**
 * CVSS score ranges mapped to severity levels
 */
export const CvssToSeverity = {
  getCritical: (score: number) => score >= 9.0,
  getHigh: (score: number) => score >= 7.0 && score < 9.0,
  getMedium: (score: number) => score >= 4.0 && score < 7.0,
  getLow: (score: number) => score >= 0.1 && score < 4.0,
  getInfo: (score: number) => score === 0.0
} as const;

/**
 * Common finding types used across security tools
 */
export const FindingTypes = {
  // Network reconnaissance
  SERVICE_DISCOVERY: 'service-discovery',
  OPEN_PORT: 'open-port',
  VULNERABLE_SERVICE: 'vulnerable-service',
  
  // DNS and domain reconnaissance  
  DNS_MISCONFIGURATION: 'dns-misconfiguration',
  SUBDOMAIN_TAKEOVER: 'subdomain-takeover',
  DOMAIN_EXPIRATION: 'domain-expiration',
  MISSING_SECURITY_HEADERS: 'missing-security-headers',
  
  // Infrastructure
  SSL_TLS_ISSUE: 'ssl-tls-issue',
  CERTIFICATE_ISSUE: 'certificate-issue',
  
  // Information disclosure
  INFORMATION_DISCLOSURE: 'information-disclosure',
  SENSITIVE_DATA_EXPOSURE: 'sensitive-data-exposure',
  
  // Misconfiguration
  SECURITY_MISCONFIGURATION: 'security-misconfiguration',
  DEFAULT_CREDENTIALS: 'default-credentials'
} as const;

/**
 * Assessment types that can generate findings
 */
export type AssessmentType = 'network-scan' | 'external-recon' | 'full-assessment' | 'custom';

/**
 * Finding storage interface for persistence
 */
export interface FindingStorage {
  /** Store a new finding */
  storeFinding(finding: SecurityFinding): Promise<void>;
  
  /** Retrieve findings by various criteria */
  getFindings(filter?: FindingFilter): Promise<SecurityFinding[]>;
  
  /** Update existing finding */
  updateFinding(id: string, updates: Partial<SecurityFinding>): Promise<void>;
  
  /** Delete finding */
  deleteFinding(id: string): Promise<void>;
  
  /** Clear all findings */
  clearFindings(): Promise<void>;
  
  /** Get findings statistics */
  getFindingStats(): Promise<FindingStats>;
}

/**
 * Filter criteria for retrieving findings
 */
export interface FindingFilter {
  /** Filter by severity levels */
  severities?: SecurityFinding['severity'][];
  
  /** Filter by finding types */
  types?: string[];
  
  /** Filter by targets */
  targets?: string[];
  
  /** Filter by discovery tool */
  discoveredBy?: string[];
  
  /** Filter by status */
  statuses?: SecurityFinding['status'][];
  
  /** Filter by date range */
  dateRange?: {
    from: Date;
    to: Date;
  };
  
  /** Limit number of results */
  limit?: number;
  
  /** Sort by field */
  sortBy?: 'discoveredAt' | 'severity' | 'target' | 'cvssScore';
  
  /** Sort direction */
  sortOrder?: 'asc' | 'desc';
}

/**
 * Statistics about stored findings
 */
export interface FindingStats {
  total: number;
  bySeverity: Record<SecurityFinding['severity'], number>;
  byType: Record<string, number>;
  byStatus: Record<SecurityFinding['status'], number>;
  mostRecentDiscovery?: Date;
  oldestDiscovery?: Date;
}

/**
 * Utility functions for working with findings
 */
export class FindingUtils {
  /**
   * Generate a unique finding ID
   */
  static generateId(target: string, type: string, port?: number): string {
    const portSuffix = port ? `-${port}` : '';
    const timestamp = Date.now().toString(36);
    return `${target}-${type}${portSuffix}-${timestamp}`;
  }
  
  /**
   * Calculate severity from CVSS score
   */
  static severityFromCvss(score: number): SecurityFinding['severity'] {
    if (CvssToSeverity.getCritical(score)) return 'critical';
    if (CvssToSeverity.getHigh(score)) return 'high';
    if (CvssToSeverity.getMedium(score)) return 'medium';
    if (CvssToSeverity.getLow(score)) return 'low';
    return 'info';
  }
  
  /**
   * Sort findings by severity (critical first)
   */
  static sortBySeverity(findings: SecurityFinding[]): SecurityFinding[] {
    return findings.sort((a, b) => SeverityLevels[b.severity] - SeverityLevels[a.severity]);
  }
  
  /**
   * Group findings by severity
   */
  static groupBySeverity(findings: SecurityFinding[]): Record<SecurityFinding['severity'], SecurityFinding[]> {
    return findings.reduce((groups, finding) => {
      if (!groups[finding.severity]) {
        groups[finding.severity] = [];
      }
      groups[finding.severity].push(finding);
      return groups;
    }, {} as Record<SecurityFinding['severity'], SecurityFinding[]>);
  }
  
  /**
   * Deduplicate findings based on target, type, and port
   */
  static deduplicate(findings: SecurityFinding[]): SecurityFinding[] {
    const seen = new Set<string>();
    return findings.filter(finding => {
      const key = `${finding.target}-${finding.type}-${finding.port || 'noport'}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }
  
  /**
   * Validate finding structure
   */
  static validate(finding: Partial<SecurityFinding>): finding is SecurityFinding {
    return !!(
      finding.id &&
      finding.severity &&
      finding.type &&
      finding.target &&
      finding.title &&
      finding.description &&
      finding.impact &&
      finding.remediation &&
      Array.isArray(finding.evidence) &&
      Array.isArray(finding.references) &&
      finding.discoveredAt &&
      finding.discoveredBy &&
      finding.status
    );
  }
}