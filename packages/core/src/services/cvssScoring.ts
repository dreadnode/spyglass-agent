/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityFinding } from '../types/security.js';

/**
 * CVSS v3.1 Base Score Metrics
 */
export interface CvssMetrics {
  /** Attack Vector (AV) */
  attackVector: 'network' | 'adjacent' | 'local' | 'physical';
  /** Attack Complexity (AC) */
  attackComplexity: 'low' | 'high';
  /** Privileges Required (PR) */
  privilegesRequired: 'none' | 'low' | 'high';
  /** User Interaction (UI) */
  userInteraction: 'none' | 'required';
  /** Scope (S) */
  scope: 'unchanged' | 'changed';
  /** Confidentiality Impact (C) */
  confidentialityImpact: 'none' | 'low' | 'high';
  /** Integrity Impact (I) */
  integrityImpact: 'none' | 'low' | 'high';
  /** Availability Impact (A) */
  availabilityImpact: 'none' | 'low' | 'high';
}

/**
 * CVSS v3.1 metric values for score calculation
 */
const CvssValues = {
  attackVector: {
    network: 0.85,
    adjacent: 0.62,
    local: 0.55,
    physical: 0.2
  },
  attackComplexity: {
    low: 0.77,
    high: 0.44
  },
  privilegesRequired: {
    // Values when scope is unchanged
    unchanged: {
      none: 0.85,
      low: 0.62,
      high: 0.27
    },
    // Values when scope is changed
    changed: {
      none: 0.85,
      low: 0.68,
      high: 0.5
    }
  },
  userInteraction: {
    none: 0.85,
    required: 0.62
  },
  impact: {
    none: 0.0,
    low: 0.22,
    high: 0.56
  }
};

/**
 * Automatic CVSS scoring engine for security findings
 */
export class CvssScorer {
  
  /**
   * Calculate CVSS score for a security finding using heuristics
   */
  static calculateScore(finding: SecurityFinding): { score: number; vector: string; metrics: CvssMetrics } {
    const metrics = this.deriveMetrics(finding);
    const score = this.computeBaseScore(metrics);
    const vector = this.generateVector(metrics);
    
    return { score, vector, metrics };
  }
  
  /**
   * Derive CVSS metrics from finding characteristics using heuristics
   */
  private static deriveMetrics(finding: SecurityFinding): CvssMetrics {
    const type = finding.type.toLowerCase();
    const description = finding.description.toLowerCase();
    const title = finding.title.toLowerCase();
    const isNetworkService = finding.port !== undefined;
    
    // Attack Vector
    let attackVector: CvssMetrics['attackVector'] = 'network';
    if (type.includes('local') || description.includes('local')) {
      attackVector = 'local';
    } else if (type.includes('physical') || description.includes('physical')) {
      attackVector = 'physical';
    } else if (type.includes('adjacent') || description.includes('lan')) {
      attackVector = 'adjacent';
    }
    
    // Attack Complexity
    let attackComplexity: CvssMetrics['attackComplexity'] = 'low';
    if (description.includes('complex') || 
        description.includes('race condition') ||
        description.includes('timing') ||
        type.includes('race') ||
        title.includes('complex')) {
      attackComplexity = 'high';
    }
    
    // Privileges Required
    let privilegesRequired: CvssMetrics['privilegesRequired'] = 'none';
    
    // Default credentials don't require privileges - that's the point
    if (type.includes('default-credentials')) {
      privilegesRequired = 'none';
    } else if (description.includes('admin') || 
               description.includes('root') || 
               description.includes('privilege') ||
               title.includes('admin')) {
      privilegesRequired = 'high';
    } else if (description.includes('user') || 
               description.includes('authenticated') ||
               description.includes('login')) {
      privilegesRequired = 'low';
    }
    
    // User Interaction
    let userInteraction: CvssMetrics['userInteraction'] = 'none';
    if (description.includes('click') || 
        description.includes('visit') || 
        description.includes('social') ||
        description.includes('phishing') ||
        type.includes('xss') ||
        type.includes('csrf')) {
      userInteraction = 'required';
    }
    
    // Scope
    let scope: CvssMetrics['scope'] = 'unchanged';
    if (type.includes('injection') || 
        type.includes('xss') || 
        type.includes('rce') ||
        type.includes('code-execution') ||
        type.includes('remote-code-execution') ||
        description.includes('remote code') ||
        description.includes('command injection') ||
        description.includes('sql injection') ||
        title.includes('remote code') ||
        title.includes('xss')) {
      scope = 'changed';
    }
    
    // Impact metrics based on finding type and severity
    const { confidentialityImpact, integrityImpact, availabilityImpact } = 
      this.deriveImpactMetrics(finding, type, description);
    
    return {
      attackVector,
      attackComplexity,
      privilegesRequired,
      userInteraction,
      scope,
      confidentialityImpact,
      integrityImpact,
      availabilityImpact
    };
  }
  
  /**
   * Derive impact metrics based on finding characteristics
   */
  private static deriveImpactMetrics(finding: SecurityFinding, type: string, description: string): {
    confidentialityImpact: CvssMetrics['confidentialityImpact'];
    integrityImpact: CvssMetrics['integrityImpact'];
    availabilityImpact: CvssMetrics['availabilityImpact'];
  } {
    let confidentialityImpact: CvssMetrics['confidentialityImpact'] = 'none';
    let integrityImpact: CvssMetrics['integrityImpact'] = 'none';
    let availabilityImpact: CvssMetrics['availabilityImpact'] = 'none';
    
    const title = finding.title.toLowerCase();
    
    // Remote code execution - always high impact
    if (type.includes('remote-code-execution') || 
        type.includes('rce') ||
        description.includes('remote code') ||
        title.includes('remote code')) {
      confidentialityImpact = 'high';
      integrityImpact = 'high';
      availabilityImpact = 'high';
      return { confidentialityImpact, integrityImpact, availabilityImpact };
    }
    
    // DoS vulnerabilities - high availability impact
    if (type.includes('denial-of-service') || 
        type.includes('dos') || 
        type.includes('denial') || 
        type.includes('crash') ||
        description.includes('crash') ||
        description.includes('unavailable') ||
        description.includes('resource exhaustion') ||
        title.includes('dos')) {
      availabilityImpact = 'high';
    }
    
    // Default credentials - high confidentiality and integrity impact
    if (type.includes('default-credentials') || 
        description.includes('default password') ||
        description.includes('admin:admin')) {
      confidentialityImpact = 'high';
      integrityImpact = 'high';
      return { confidentialityImpact, integrityImpact, availabilityImpact };
    }
    
    // High impact scenarios based on severity
    if (finding.severity === 'critical' || finding.severity === 'high') {
      if (type.includes('disclosure') || 
          type.includes('exposure') || 
          type.includes('leak') ||
          description.includes('credential') ||
          description.includes('password') ||
          description.includes('private key')) {
        confidentialityImpact = 'high';
      }
      
      if (type.includes('injection') || 
          type.includes('upload') ||
          description.includes('modify') ||
          description.includes('write') ||
          description.includes('admin access')) {
        integrityImpact = 'high';
      }
    }
    
    // Medium impact scenarios
    if (finding.severity === 'medium') {
      if (type.includes('information') || 
          type.includes('disclosure') ||
          description.includes('enumerate') ||
          description.includes('reveal')) {
        confidentialityImpact = 'low';
      }
      
      if (type.includes('misconfiguration') || 
          description.includes('weak') ||
          description.includes('default')) {
        integrityImpact = 'low';
        availabilityImpact = 'low';
      }
    }
    
    // Service discovery and reconnaissance - low confidentiality impact
    if (type.includes('service-discovery') || 
        type.includes('open-port') ||
        type.includes('dns')) {
      confidentialityImpact = 'low';
    }
    
    // Vulnerable services should have some impact even if severity is medium
    if (type.includes('vulnerable-service')) {
      if (confidentialityImpact === 'none') confidentialityImpact = 'low';
      if (integrityImpact === 'none') integrityImpact = 'low';
    }
    
    // Default credentials and weak authentication
    if (type.includes('default-credentials') || 
        type.includes('weak-auth') ||
        description.includes('default password')) {
      confidentialityImpact = 'high';
      integrityImpact = 'high';
      availabilityImpact = 'low';
    }
    
    // SSL/TLS issues
    if (type.includes('ssl') || 
        type.includes('tls') || 
        type.includes('certificate')) {
      confidentialityImpact = 'low';
      integrityImpact = 'low';
    }
    
    return { confidentialityImpact, integrityImpact, availabilityImpact };
  }
  
  /**
   * Compute CVSS v3.1 base score from metrics
   */
  private static computeBaseScore(metrics: CvssMetrics): number {
    // Get metric values
    const av = CvssValues.attackVector[metrics.attackVector];
    const ac = CvssValues.attackComplexity[metrics.attackComplexity];
    const ui = CvssValues.userInteraction[metrics.userInteraction];
    
    // Privileges Required depends on scope
    const pr = metrics.scope === 'changed' 
      ? CvssValues.privilegesRequired.changed[metrics.privilegesRequired]
      : CvssValues.privilegesRequired.unchanged[metrics.privilegesRequired];
    
    // Impact values
    const c = CvssValues.impact[metrics.confidentialityImpact];
    const i = CvssValues.impact[metrics.integrityImpact];
    const a = CvssValues.impact[metrics.availabilityImpact];
    
    // Calculate ISC (Impact Sub-score)
    const isc = 1 - ((1 - c) * (1 - i) * (1 - a));
    
    // Calculate Impact
    let impact: number;
    if (metrics.scope === 'unchanged') {
      impact = 6.42 * isc;
    } else {
      impact = 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.02, 15);
    }
    
    // Calculate Exploitability
    const exploitability = 8.22 * av * ac * pr * ui;
    
    // Calculate Base Score
    let baseScore: number;
    if (impact <= 0) {
      baseScore = 0;
    } else if (metrics.scope === 'unchanged') {
      baseScore = Math.min(impact + exploitability, 10);
    } else {
      baseScore = Math.min(1.08 * (impact + exploitability), 10);
    }
    
    // Round to one decimal place
    return Math.round(baseScore * 10) / 10;
  }
  
  /**
   * Generate CVSS v3.1 vector string from metrics
   */
  private static generateVector(metrics: CvssMetrics): string {
    const vectorMap = {
      attackVector: {
        network: 'N',
        adjacent: 'A',
        local: 'L',
        physical: 'P'
      },
      attackComplexity: {
        low: 'L',
        high: 'H'
      },
      privilegesRequired: {
        none: 'N',
        low: 'L',
        high: 'H'
      },
      userInteraction: {
        none: 'N',
        required: 'R'
      },
      scope: {
        unchanged: 'U',
        changed: 'C'
      },
      impact: {
        none: 'N',
        low: 'L',
        high: 'H'
      }
    };
    
    return `CVSS:3.1/AV:${vectorMap.attackVector[metrics.attackVector]}/AC:${vectorMap.attackComplexity[metrics.attackComplexity]}/PR:${vectorMap.privilegesRequired[metrics.privilegesRequired]}/UI:${vectorMap.userInteraction[metrics.userInteraction]}/S:${vectorMap.scope[metrics.scope]}/C:${vectorMap.impact[metrics.confidentialityImpact]}/I:${vectorMap.impact[metrics.integrityImpact]}/A:${vectorMap.impact[metrics.availabilityImpact]}`;
  }
  
  /**
   * Update a finding with calculated CVSS score and vector
   */
  static scoreFinding(finding: SecurityFinding): SecurityFinding {
    const { score, vector } = this.calculateScore(finding);
    
    return {
      ...finding,
      cvssScore: score,
      cvssVector: vector
    };
  }
  
  /**
   * Batch score multiple findings
   */
  static scoreFindings(findings: SecurityFinding[]): SecurityFinding[] {
    return findings.map(finding => this.scoreFinding(finding));
  }
  
  /**
   * Calculate risk level based on CVSS score and other factors
   */
  static calculateRiskLevel(finding: SecurityFinding): {
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
    riskScore: number;
    factors: string[];
  } {
    const cvssResult = this.calculateScore(finding);
    const baseScore = cvssResult.score;
    
    const factors: string[] = [];
    let multiplier = 1.0;
    
    // Network exposure increases risk
    if (finding.port !== undefined) {
      multiplier += 0.1;
      factors.push('Network exposed service');
    }
    
    // Default credentials are high risk regardless of CVSS
    if (finding.type.includes('default-credentials')) {
      multiplier += 0.3;
      factors.push('Default credentials present');
    }
    
    // Remote code execution is critical
    if (finding.description.toLowerCase().includes('remote code') || 
        finding.type.includes('rce')) {
      multiplier += 0.5;
      factors.push('Remote code execution possible');
    }
    
    // Information disclosure in production
    if (finding.type.includes('disclosure') || finding.type.includes('exposure')) {
      multiplier += 0.2;
      factors.push('Information disclosure');
    }
    
    // SSL/TLS issues on production services
    if ((finding.type.includes('ssl') || finding.type.includes('tls')) && finding.port) {
      multiplier += 0.15;
      factors.push('Cryptographic weakness');
    }
    
    const adjustedScore = Math.min(10, baseScore * multiplier);
    
    // Determine risk level
    let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
    if (adjustedScore >= 9.0) {
      riskLevel = 'critical';
    } else if (adjustedScore >= 7.0) {
      riskLevel = 'high';
    } else if (adjustedScore >= 4.0) {
      riskLevel = 'medium';
    } else if (adjustedScore >= 0.1) {
      riskLevel = 'low';
    } else {
      riskLevel = 'info';
    }
    
    return {
      riskLevel,
      riskScore: Math.round(adjustedScore * 10) / 10,
      factors
    };
  }
}