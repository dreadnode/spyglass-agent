/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityFinding, FindingStorage, FindingFilter, FindingStats, FindingUtils } from '../types/security.js';
import { FindingCorrelator, CorrelationResult, CorrelatedFinding } from './findingCorrelation.js';
import { CvssScorer } from './cvssScoring.js';
import path from 'path';
import { promises as fs } from 'fs';

/**
 * Centralized finding storage that persists findings to a JSON database file
 * and provides structured access for security tools and reporting
 */
export class MemoryFindingStorage implements FindingStorage {
  private static instance: MemoryFindingStorage | null = null;
  private findingsCache: SecurityFinding[] = [];
  private correlatedGroups: CorrelatedFinding[] = [];
  private cacheLoaded = false;
  private correlationCacheValid = false;
  
  private constructor(private targetDir: string) {}
  
  /**
   * Get singleton instance of MemoryFindingStorage
   */
  static getInstance(targetDir: string): MemoryFindingStorage {
    if (!MemoryFindingStorage.instance) {
      MemoryFindingStorage.instance = new MemoryFindingStorage(targetDir);
    }
    return MemoryFindingStorage.instance;
  }
  
  /**
   * Get the findings database file path
   */
  private getFindingsDbPath(): string {
    return path.join(this.targetDir, '.spyglass', 'findings.json');
  }
  
  /**
   * Load findings from the database file
   */
  private async loadFindings(): Promise<void> {
    if (this.cacheLoaded) return;
    
    try {
      const dbPath = this.getFindingsDbPath();
      const data = await fs.readFile(dbPath, 'utf8');
      const parsed = JSON.parse(data);
      
      // Validate and convert date strings back to Date objects
      this.findingsCache = parsed.findings?.map((f: any) => ({
        ...f,
        discoveredAt: new Date(f.discoveredAt)
      })) || [];
      
      console.log(`[DEBUG] FindingStorage: Loaded ${this.findingsCache.length} findings from database`);
    } catch (error) {
      // File doesn't exist or is invalid, start with empty cache
      this.findingsCache = [];
      console.log('[DEBUG] FindingStorage: Starting with empty findings database');
    }
    
    this.cacheLoaded = true;
  }
  
  /**
   * Save findings to the database file
   */
  private async saveFindings(): Promise<void> {
    try {
      const dbPath = this.getFindingsDbPath();
      const dir = path.dirname(dbPath);
      
      // Ensure directory exists
      await fs.mkdir(dir, { recursive: true });
      
      const data = {
        version: '1.0',
        lastUpdated: new Date().toISOString(),
        findings: this.findingsCache
      };
      
      await fs.writeFile(dbPath, JSON.stringify(data, null, 2), 'utf8');
      console.log(`[DEBUG] FindingStorage: Saved ${this.findingsCache.length} findings to database`);
    } catch (error) {
      console.error(`[ERROR] FindingStorage: Failed to save findings: ${error}`);
      throw error;
    }
  }
  
  /**
   * Log finding summary for debugging
   */
  private logFindingSummary(finding: SecurityFinding): void {
    console.log(`[INFO] FindingStorage: ${finding.severity.toUpperCase()} finding - ${finding.title} on ${finding.target}${finding.port ? `:${finding.port}` : ''}`);
  }
  
  /**
   * Store a new security finding with automatic deduplication and CVSS scoring
   */
  async storeFinding(finding: SecurityFinding): Promise<void> {
    await this.loadFindings();
    
    // Validate finding
    if (!FindingUtils.validate(finding)) {
      throw new Error(`Invalid security finding: missing required fields`);
    }
    
    // Automatically calculate CVSS score if not provided
    let processedFinding = finding;
    if (!finding.cvssScore || !finding.cvssVector) {
      processedFinding = CvssScorer.scoreFinding(finding);
      console.log(`[DEBUG] FindingStorage: Auto-calculated CVSS score ${processedFinding.cvssScore} for finding ${finding.id}`);
    }
    
    // Check for exact duplicates (same ID)
    const existingIndex = this.findingsCache.findIndex(f => f.id === processedFinding.id);
    if (existingIndex >= 0) {
      // Update existing finding
      this.findingsCache[existingIndex] = processedFinding;
      console.log(`[INFO] FindingStorage: Updated existing finding ${processedFinding.id}`);
    } else {
      // Check for semantic duplicates before adding
      const semanticDuplicate = this.findSemanticDuplicate(processedFinding);
      if (semanticDuplicate) {
        // Merge with existing finding
        await this.mergeFinding(semanticDuplicate, processedFinding);
        console.log(`[INFO] FindingStorage: Merged finding ${processedFinding.id} with existing ${semanticDuplicate.id}`);
      } else {
        // Add new finding
        this.findingsCache.push(processedFinding);
        console.log(`[INFO] FindingStorage: Stored new finding ${processedFinding.id} (${processedFinding.severity}: ${processedFinding.title})`);
      }
    }
    
    // Invalidate correlation cache
    this.correlationCacheValid = false;
    
    // Save to database
    await this.saveFindings();
    
    // Log finding summary for debugging
    this.logFindingSummary(processedFinding);
  }
  
  /**
   * Find semantic duplicate of a finding
   */
  private findSemanticDuplicate(finding: SecurityFinding): SecurityFinding | null {
    const semanticKey = this.getSemanticKey(finding);
    return this.findingsCache.find(existing => 
      this.getSemanticKey(existing) === semanticKey
    ) || null;
  }
  
  /**
   * Generate semantic key for deduplication
   */
  private getSemanticKey(finding: SecurityFinding): string {
    const normalizedTarget = finding.target
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '')
      .toLowerCase();
    return `${normalizedTarget}:${finding.type}:${finding.port || 'none'}`;
  }
  
  /**
   * Merge a new finding with an existing one
   */
  private async mergeFinding(existing: SecurityFinding, newFinding: SecurityFinding): Promise<void> {
    // Merge evidence and references
    const mergedEvidence = [...new Set([...existing.evidence, ...newFinding.evidence])];
    const mergedReferences = [...new Set([...existing.references, ...newFinding.references])];
    
    // Use the most severe finding as base
    const shouldReplace = this.shouldReplaceFinding(existing, newFinding);
    const baseFinding = shouldReplace ? newFinding : existing;
    
    // Update the existing finding
    const index = this.findingsCache.findIndex(f => f.id === existing.id);
    this.findingsCache[index] = {
      ...baseFinding,
      id: existing.id, // Keep original ID
      evidence: mergedEvidence,
      references: mergedReferences,
      discoveredBy: `${existing.discoveredBy}, ${newFinding.discoveredBy}`
    };
  }
  
  /**
   * Determine if a new finding should replace an existing one
   */
  private shouldReplaceFinding(existing: SecurityFinding, newFinding: SecurityFinding): boolean {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const existingIdx = severityOrder.indexOf(existing.severity);
    const newIdx = severityOrder.indexOf(newFinding.severity);
    
    // Replace if new finding is more severe
    if (newIdx < existingIdx) return true;
    if (existingIdx < newIdx) return false;
    
    // Same severity - prefer one with more evidence
    return newFinding.evidence.length > existing.evidence.length;
  }
  
  /**
   * Retrieve findings with optional filtering
   */
  async getFindings(filter?: FindingFilter): Promise<SecurityFinding[]> {
    await this.loadFindings();
    
    let results = [...this.findingsCache];
    
    if (filter) {
      // Apply filters
      if (filter.severities?.length) {
        results = results.filter(f => filter.severities!.includes(f.severity));
      }
      
      if (filter.types?.length) {
        results = results.filter(f => filter.types!.includes(f.type));
      }
      
      if (filter.targets?.length) {
        results = results.filter(f => filter.targets!.some(target => f.target.includes(target)));
      }
      
      if (filter.discoveredBy?.length) {
        results = results.filter(f => filter.discoveredBy!.includes(f.discoveredBy));
      }
      
      if (filter.statuses?.length) {
        results = results.filter(f => filter.statuses!.includes(f.status));
      }
      
      if (filter.dateRange) {
        results = results.filter(f => 
          f.discoveredAt >= filter.dateRange!.from && 
          f.discoveredAt <= filter.dateRange!.to
        );
      }
      
      // Apply sorting
      if (filter.sortBy) {
        results.sort((a, b) => {
          let aVal: any, bVal: any;
          
          switch (filter.sortBy) {
            case 'severity':
              aVal = ['critical', 'high', 'medium', 'low', 'info'].indexOf(a.severity);
              bVal = ['critical', 'high', 'medium', 'low', 'info'].indexOf(b.severity);
              break;
            case 'discoveredAt':
              aVal = a.discoveredAt.getTime();
              bVal = b.discoveredAt.getTime();
              break;
            case 'target':
              aVal = a.target;
              bVal = b.target;
              break;
            case 'cvssScore':
              aVal = a.cvssScore || 0;
              bVal = b.cvssScore || 0;
              break;
            default:
              return 0;
          }
          
          const comparison = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
          return filter.sortOrder === 'desc' ? -comparison : comparison;
        });
      }
      
      // Apply limit
      if (filter.limit) {
        results = results.slice(0, filter.limit);
      }
    }
    
    return results;
  }
  
  /**
   * Update an existing finding
   */
  async updateFinding(id: string, updates: Partial<SecurityFinding>): Promise<void> {
    await this.loadFindings();
    
    const index = this.findingsCache.findIndex(f => f.id === id);
    if (index === -1) {
      throw new Error(`Finding with id ${id} not found`);
    }
    
    // Merge updates
    this.findingsCache[index] = { ...this.findingsCache[index], ...updates };
    
    await this.saveFindings();
    console.log(`[INFO] FindingStorage: Updated finding ${id}`);
  }
  
  /**
   * Delete a finding
   */
  async deleteFinding(id: string): Promise<void> {
    await this.loadFindings();
    
    const index = this.findingsCache.findIndex(f => f.id === id);
    if (index === -1) {
      throw new Error(`Finding with id ${id} not found`);
    }
    
    this.findingsCache.splice(index, 1);
    await this.saveFindings();
    console.log(`[INFO] FindingStorage: Deleted finding ${id}`);
  }
  
  /**
   * Clear all findings
   */
  async clearFindings(): Promise<void> {
    this.findingsCache = [];
    await this.saveFindings();
    console.log('[INFO] FindingStorage: Cleared all findings');
  }
  
  /**
   * Get statistics about stored findings
   */
  async getFindingStats(): Promise<FindingStats> {
    await this.loadFindings();
    
    const stats: FindingStats = {
      total: this.findingsCache.length,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      byType: {},
      byStatus: {
        new: 0,
        confirmed: 0,
        'false-positive': 0,
        remediated: 0,
        'accepted-risk': 0
      }
    };
    
    if (this.findingsCache.length === 0) {
      return stats;
    }
    
    // Calculate statistics
    for (const finding of this.findingsCache) {
      // By severity
      stats.bySeverity[finding.severity]++;
      
      // By type
      stats.byType[finding.type] = (stats.byType[finding.type] || 0) + 1;
      
      // By status
      stats.byStatus[finding.status]++;
    }
    
    // Date range
    const dates = this.findingsCache.map(f => f.discoveredAt).sort((a, b) => a.getTime() - b.getTime());
    stats.oldestDiscovery = dates[0];
    stats.mostRecentDiscovery = dates[dates.length - 1];
    
    return stats;
  }
  
  /**
   * Get correlated findings with deduplication and relationship analysis
   */
  async getCorrelatedFindings(): Promise<CorrelationResult> {
    await this.loadFindings();
    
    if (!this.correlationCacheValid) {
      console.log('[INFO] FindingStorage: Performing finding correlation and deduplication...');
      const correlationResult = FindingCorrelator.correlateFindings(this.findingsCache);
      
      // Update cache with deduplicated findings
      this.findingsCache = correlationResult.uniqueFindings;
      this.correlatedGroups = correlationResult.correlatedGroups;
      this.correlationCacheValid = true;
      
      // Save deduplicated findings
      await this.saveFindings();
      
      console.log(`[INFO] FindingStorage: Correlation complete - ${correlationResult.stats.duplicatesRemoved} duplicates removed, ${correlationResult.stats.correlationGroups} correlation groups found`);
      
      return correlationResult;
    }
    
    return {
      uniqueFindings: this.findingsCache,
      correlatedGroups: this.correlatedGroups,
      stats: {
        originalCount: this.findingsCache.length,
        uniqueCount: this.findingsCache.length,
        duplicatesRemoved: 0,
        correlationGroups: this.correlatedGroups.length
      }
    };
  }
  
  /**
   * Get findings with relationships (correlated groups)
   */
  async getFindingsWithRelationships(): Promise<{
    findings: SecurityFinding[];
    relationships: CorrelatedFinding[];
  }> {
    const correlation = await this.getCorrelatedFindings();
    return {
      findings: correlation.uniqueFindings,
      relationships: correlation.correlatedGroups
    };
  }
  
  /**
   * Force recomputation of correlations
   */
  async recomputeCorrelations(): Promise<CorrelationResult> {
    this.correlationCacheValid = false;
    return await this.getCorrelatedFindings();
  }
  
  /**
   * Recalculate CVSS scores for all findings
   */
  async recalculateCvssScores(): Promise<void> {
    await this.loadFindings();
    
    console.log(`[INFO] FindingStorage: Recalculating CVSS scores for ${this.findingsCache.length} findings...`);
    
    let updated = 0;
    for (let i = 0; i < this.findingsCache.length; i++) {
      const finding = this.findingsCache[i];
      const scoredFinding = CvssScorer.scoreFinding(finding);
      
      // Update if score changed or was missing
      if (!finding.cvssScore || finding.cvssScore !== scoredFinding.cvssScore) {
        this.findingsCache[i] = scoredFinding;
        updated++;
      }
    }
    
    if (updated > 0) {
      await this.saveFindings();
      console.log(`[INFO] FindingStorage: Updated CVSS scores for ${updated} findings`);
    } else {
      console.log(`[INFO] FindingStorage: All CVSS scores are current`);
    }
  }
  
  /**
   * Get risk statistics based on CVSS scores
   */
  async getRiskStatistics(): Promise<{
    averageCvssScore: number;
    highestCvssScore: number;
    findingsWithoutCvss: number;
    riskDistribution: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
  }> {
    await this.loadFindings();
    
    const withCvss = this.findingsCache.filter(f => f.cvssScore !== undefined);
    const withoutCvss = this.findingsCache.length - withCvss.length;
    
    const averageCvssScore = withCvss.length > 0 
      ? withCvss.reduce((sum, f) => sum + f.cvssScore!, 0) / withCvss.length 
      : 0;
    
    const highestCvssScore = withCvss.length > 0 
      ? Math.max(...withCvss.map(f => f.cvssScore!)) 
      : 0;
    
    // Calculate risk distribution using CVSS-based severity
    const riskDistribution = {
      critical: 0,
      high: 0, 
      medium: 0,
      low: 0,
      info: 0
    };
    
    withCvss.forEach(finding => {
      const risk = CvssScorer.calculateRiskLevel(finding);
      riskDistribution[risk.riskLevel]++;
    });
    
    return {
      averageCvssScore: Math.round(averageCvssScore * 10) / 10,
      highestCvssScore,
      findingsWithoutCvss: withoutCvss,
      riskDistribution
    };
  }
  
  /**
   * Export findings to various formats
   */
  async exportFindings(format: 'json' | 'csv' | 'summary' | 'correlated'): Promise<string> {
    await this.loadFindings();
    
    switch (format) {
      case 'json':
        return JSON.stringify(this.findingsCache, null, 2);
        
      case 'csv':
        if (this.findingsCache.length === 0) return 'No findings to export';
        
        const headers = ['ID', 'Severity', 'Type', 'Target', 'Port', 'Title', 'Description', 'Impact', 'Remediation', 'Status', 'Discovered By', 'Discovered At'];
        const rows = this.findingsCache.map(f => [
          f.id,
          f.severity,
          f.type,
          f.target,
          f.port || '',
          f.title,
          f.description,
          f.impact,
          f.remediation,
          f.status,
          f.discoveredBy,
          f.discoveredAt.toISOString()
        ]);
        
        return [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
        
      case 'summary':
        const stats = await this.getFindingStats();
        return `Security Findings Summary:
Total Findings: ${stats.total}
Critical: ${stats.bySeverity.critical}
High: ${stats.bySeverity.high}
Medium: ${stats.bySeverity.medium}
Low: ${stats.bySeverity.low}
Info: ${stats.bySeverity.info}

Most Recent Discovery: ${stats.mostRecentDiscovery?.toISOString() || 'None'}
Oldest Discovery: ${stats.oldestDiscovery?.toISOString() || 'None'}`;

      case 'correlated':
        const correlationResult = await this.getCorrelatedFindings();
        return JSON.stringify({
          correlation_stats: correlationResult.stats,
          unique_findings: correlationResult.uniqueFindings,
          correlation_groups: correlationResult.correlatedGroups
        }, null, 2);
        
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }
}