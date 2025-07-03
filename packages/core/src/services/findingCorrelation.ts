/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityFinding, FindingTypes } from '../types/security.js';

/**
 * Advanced finding correlation and deduplication logic
 */
export interface CorrelatedFinding {
  /** Primary finding */
  primary: SecurityFinding;
  /** Related findings that were merged or correlated */
  related: SecurityFinding[];
  /** Confidence score of the correlation (0-1) */
  confidence: number;
  /** Correlation type */
  type: 'duplicate' | 'related' | 'chain';
}

/**
 * Result of deduplication and correlation process
 */
export interface CorrelationResult {
  /** Unique findings after deduplication */
  uniqueFindings: SecurityFinding[];
  /** Correlated finding groups */
  correlatedGroups: CorrelatedFinding[];
  /** Statistics about the correlation process */
  stats: {
    originalCount: number;
    uniqueCount: number;
    duplicatesRemoved: number;
    correlationGroups: number;
  };
}

/**
 * Advanced finding correlation engine
 */
export class FindingCorrelator {
  
  /**
   * Perform advanced deduplication and correlation on a set of findings
   */
  static correlateFindings(findings: SecurityFinding[]): CorrelationResult {
    const originalCount = findings.length;
    
    // Step 1: Exact deduplication (same ID)
    const dedupedById = this.deduplicateById(findings);
    
    // Step 2: Semantic deduplication (same target+type+port but different IDs)
    const { unique: semanticUnique, duplicates: semanticDups } = this.deduplicateSemantic(dedupedById);
    
    // Step 3: Find related findings that should be correlated
    const { correlated, remaining } = this.correlateRelated(semanticUnique);
    
    // Step 4: Create attack chains
    const attackChains = this.identifyAttackChains(remaining);
    
    const uniqueCount = remaining.length;
    const duplicatesRemoved = originalCount - uniqueCount;
    
    return {
      uniqueFindings: remaining,
      correlatedGroups: [...semanticDups, ...correlated, ...attackChains],
      stats: {
        originalCount,
        uniqueCount,
        duplicatesRemoved,
        correlationGroups: semanticDups.length + correlated.length + attackChains.length
      }
    };
  }
  
  /**
   * Remove exact duplicates by ID
   */
  private static deduplicateById(findings: SecurityFinding[]): SecurityFinding[] {
    const seen = new Set<string>();
    return findings.filter(finding => {
      if (seen.has(finding.id)) {
        return false;
      }
      seen.add(finding.id);
      return true;
    });
  }
  
  /**
   * Remove semantic duplicates (same target+type+port but different discovery times/tools)
   */
  private static deduplicateSemantic(findings: SecurityFinding[]): {
    unique: SecurityFinding[];
    duplicates: CorrelatedFinding[];
  } {
    const groups = new Map<string, SecurityFinding[]>();
    
    // Group by semantic key
    for (const finding of findings) {
      const key = this.getSemanticKey(finding);
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key)!.push(finding);
    }
    
    const unique: SecurityFinding[] = [];
    const duplicates: CorrelatedFinding[] = [];
    
    for (const [key, group] of groups) {
      if (group.length === 1) {
        unique.push(group[0]);
      } else {
        // Multiple findings with same semantic meaning - merge them
        const primary = this.selectPrimaryFinding(group);
        const related = group.filter(f => f.id !== primary.id);
        
        // Merge evidence and references
        const mergedFinding: SecurityFinding = {
          ...primary,
          evidence: [...new Set([...primary.evidence, ...related.flatMap(f => f.evidence)])],
          references: [...new Set([...primary.references, ...related.flatMap(f => f.references)])],
          discoveredBy: this.mergeDiscoveryInfo(group)
        };
        
        unique.push(mergedFinding);
        duplicates.push({
          primary: mergedFinding,
          related,
          confidence: 1.0, // Exact semantic match
          type: 'duplicate'
        });
      }
    }
    
    return { unique, duplicates };
  }
  
  /**
   * Generate semantic key for finding deduplication
   */
  private static getSemanticKey(finding: SecurityFinding): string {
    // Normalize target (remove protocol, trailing slashes, etc.)
    const normalizedTarget = finding.target
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '')
      .toLowerCase();
    
    return `${normalizedTarget}:${finding.type}:${finding.port || 'none'}`;
  }
  
  /**
   * Select the best finding as primary when merging duplicates
   */
  private static selectPrimaryFinding(findings: SecurityFinding[]): SecurityFinding {
    // Prefer findings with:
    // 1. Higher severity
    // 2. More evidence
    // 3. More recent discovery
    // 4. Better tool (preference order)
    
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const toolPreference = ['NetworkReconTool', 'ExternalReconTool', 'manual'];
    
    return findings.sort((a, b) => {
      // 1. Severity
      const aSevIdx = severityOrder.indexOf(a.severity);
      const bSevIdx = severityOrder.indexOf(b.severity);
      if (aSevIdx !== bSevIdx) return aSevIdx - bSevIdx;
      
      // 2. Evidence count
      if (a.evidence.length !== b.evidence.length) {
        return b.evidence.length - a.evidence.length;
      }
      
      // 3. Discovery time (more recent first)
      if (a.discoveredAt.getTime() !== b.discoveredAt.getTime()) {
        return b.discoveredAt.getTime() - a.discoveredAt.getTime();
      }
      
      // 4. Tool preference
      const aToolIdx = toolPreference.indexOf(a.discoveredBy);
      const bToolIdx = toolPreference.indexOf(b.discoveredBy);
      return (aToolIdx === -1 ? 999 : aToolIdx) - (bToolIdx === -1 ? 999 : bToolIdx);
    })[0];
  }
  
  /**
   * Merge discovery information from multiple findings
   */
  private static mergeDiscoveryInfo(findings: SecurityFinding[]): string {
    const tools = [...new Set(findings.map(f => f.discoveredBy))];
    if (tools.length === 1) return tools[0];
    return `Multiple tools: ${tools.join(', ')}`;
  }
  
  /**
   * Find related findings that should be correlated (same target, related types)
   */
  private static correlateRelated(findings: SecurityFinding[]): {
    correlated: CorrelatedFinding[];
    remaining: SecurityFinding[];
  } {
    const correlated: CorrelatedFinding[] = [];
    const used = new Set<string>();
    const remaining: SecurityFinding[] = [];
    
    // Group findings by target
    const targetGroups = this.groupByTarget(findings);
    
    for (const [target, targetFindings] of targetGroups) {
      const correlations = this.findTargetCorrelations(targetFindings);
      
      for (const correlation of correlations) {
        correlated.push(correlation);
        // Mark all findings in this correlation as used
        used.add(correlation.primary.id);
        correlation.related.forEach(f => used.add(f.id));
      }
    }
    
    // Add unused findings to remaining
    for (const finding of findings) {
      if (!used.has(finding.id)) {
        remaining.push(finding);
      }
    }
    
    return { correlated, remaining };
  }
  
  /**
   * Group findings by normalized target
   */
  private static groupByTarget(findings: SecurityFinding[]): Map<string, SecurityFinding[]> {
    const groups = new Map<string, SecurityFinding[]>();
    
    for (const finding of findings) {
      const normalizedTarget = finding.target.toLowerCase();
      if (!groups.has(normalizedTarget)) {
        groups.set(normalizedTarget, []);
      }
      groups.get(normalizedTarget)!.push(finding);
    }
    
    return groups;
  }
  
  /**
   * Find correlations within findings for the same target
   */
  private static findTargetCorrelations(findings: SecurityFinding[]): CorrelatedFinding[] {
    const correlations: CorrelatedFinding[] = [];
    
    // Look for SSL/TLS and certificate issues that should be grouped
    const sslFindings = findings.filter(f => 
      f.type === FindingTypes.SSL_TLS_ISSUE || 
      f.type === FindingTypes.CERTIFICATE_ISSUE
    );
    
    if (sslFindings.length > 1) {
      const primary = sslFindings[0];
      const related = sslFindings.slice(1);
      correlations.push({
        primary,
        related,
        confidence: 0.8,
        type: 'related'
      });
    }
    
    // Look for service discovery that enables other vulnerabilities
    const serviceFindings = findings.filter(f => f.type === FindingTypes.SERVICE_DISCOVERY);
    const vulnFindings = findings.filter(f => 
      f.type === FindingTypes.VULNERABLE_SERVICE ||
      f.type === FindingTypes.DEFAULT_CREDENTIALS
    );
    
    for (const service of serviceFindings) {
      const relatedVulns = vulnFindings.filter(vuln => 
        vuln.port === service.port || 
        vuln.description.includes(service.title)
      );
      
      if (relatedVulns.length > 0) {
        correlations.push({
          primary: service,
          related: relatedVulns,
          confidence: 0.7,
          type: 'related'
        });
      }
    }
    
    return correlations;
  }
  
  /**
   * Identify attack chains across multiple targets
   */
  private static identifyAttackChains(findings: SecurityFinding[]): CorrelatedFinding[] {
    const chains: CorrelatedFinding[] = [];
    
    // Look for DNS findings that could lead to subdomain takeover
    const dnsFindings = findings.filter(f => f.type === FindingTypes.DNS_MISCONFIGURATION);
    const takeoverFindings = findings.filter(f => f.type === FindingTypes.SUBDOMAIN_TAKEOVER);
    
    for (const dns of dnsFindings) {
      const relatedTakeover = takeoverFindings.filter(takeover =>
        takeover.target.includes(dns.target) || dns.target.includes(takeover.target)
      );
      
      if (relatedTakeover.length > 0) {
        chains.push({
          primary: dns,
          related: relatedTakeover,
          confidence: 0.9,
          type: 'chain'
        });
      }
    }
    
    // Look for information disclosure that could lead to credential attacks
    const infoDisclosure = findings.filter(f => 
      f.type === FindingTypes.INFORMATION_DISCLOSURE ||
      f.type === FindingTypes.SENSITIVE_DATA_EXPOSURE
    );
    const credentialFindings = findings.filter(f => f.type === FindingTypes.DEFAULT_CREDENTIALS);
    
    for (const info of infoDisclosure) {
      if (info.description.toLowerCase().includes('credential') || 
          info.description.toLowerCase().includes('password')) {
        const relatedCreds = credentialFindings.filter(cred =>
          this.targetsAreRelated(info.target, cred.target)
        );
        
        if (relatedCreds.length > 0) {
          chains.push({
            primary: info,
            related: relatedCreds,
            confidence: 0.6,
            type: 'chain'
          });
        }
      }
    }
    
    return chains;
  }
  
  /**
   * Check if two targets are related (same domain, subnet, etc.)
   */
  private static targetsAreRelated(target1: string, target2: string): boolean {
    // Simple heuristic - could be enhanced with proper domain/IP parsing
    const normalize = (target: string) => target.toLowerCase().replace(/^https?:\/\//, '');
    const norm1 = normalize(target1);
    const norm2 = normalize(target2);
    
    // Same target
    if (norm1 === norm2) return true;
    
    // Same domain
    const domain1 = norm1.split('.').slice(-2).join('.');
    const domain2 = norm2.split('.').slice(-2).join('.');
    if (domain1 === domain2 && domain1.includes('.')) return true;
    
    // Same subnet (basic check for /24)
    const ip1Parts = norm1.split('.');
    const ip2Parts = norm2.split('.');
    if (ip1Parts.length === 4 && ip2Parts.length === 4) {
      return ip1Parts.slice(0, 3).join('.') === ip2Parts.slice(0, 3).join('.');
    }
    
    return false;
  }
  
  /**
   * Calculate risk score for a correlated finding group
   */
  static calculateGroupRiskScore(group: CorrelatedFinding): number {
    const severityScores = {
      'critical': 10,
      'high': 7,
      'medium': 4,
      'low': 2,
      'info': 1
    };
    
    const primaryScore = severityScores[group.primary.severity];
    const relatedScore = group.related.reduce((sum, f) => sum + severityScores[f.severity], 0);
    
    // Apply correlation multiplier
    const correlationMultiplier = group.type === 'chain' ? 1.5 : 
                                  group.type === 'related' ? 1.2 : 1.0;
    
    return Math.min(10, (primaryScore + relatedScore * 0.3) * correlationMultiplier * group.confidence);
  }
}