/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityFinding, FindingStorage, FindingFilter, FindingStats, FindingUtils } from '../types/security.js';
import path from 'path';
import { promises as fs } from 'fs';

/**
 * Centralized finding storage that persists findings to a JSON database file
 * and provides structured access for security tools and reporting
 */
export class MemoryFindingStorage implements FindingStorage {
  private static instance: MemoryFindingStorage | null = null;
  private findingsCache: SecurityFinding[] = [];
  private cacheLoaded = false;
  
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
   * Store a new security finding
   */
  async storeFinding(finding: SecurityFinding): Promise<void> {
    await this.loadFindings();
    
    // Validate finding
    if (!FindingUtils.validate(finding)) {
      throw new Error(`Invalid security finding: missing required fields`);
    }
    
    // Check for duplicates
    const existingIndex = this.findingsCache.findIndex(f => f.id === finding.id);
    if (existingIndex >= 0) {
      // Update existing finding
      this.findingsCache[existingIndex] = finding;
      console.log(`[INFO] FindingStorage: Updated existing finding ${finding.id}`);
    } else {
      // Add new finding
      this.findingsCache.push(finding);
      console.log(`[INFO] FindingStorage: Stored new finding ${finding.id} (${finding.severity}: ${finding.title})`);
    }
    
    // Save to database
    await this.saveFindings();
    
    // Log finding summary for debugging
    this.logFindingSummary(finding);
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
   * Export findings to various formats
   */
  async exportFindings(format: 'json' | 'csv' | 'summary'): Promise<string> {
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
        
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }
}