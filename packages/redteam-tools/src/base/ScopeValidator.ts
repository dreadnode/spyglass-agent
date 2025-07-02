/**
 * Scope validation system for red team engagements
 * 
 * This class ensures all security testing activities remain within
 * authorized scope and maintains proper audit trails.
 */

import { EngagementScope } from '../types/index.js';

export class ScopeValidator {
  private scope: EngagementScope;
  private auditLog: Array<{
    timestamp: Date;
    action: string;
    target: string;
    user: string;
    allowed: boolean;
    reason?: string;
  }> = [];

  constructor(scope: EngagementScope) {
    this.scope = scope;
  }

  /**
   * Validate if a target is within the approved engagement scope
   */
  async validateTarget(target: string, user: string): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      // Check if engagement is active
      const now = new Date();
      if (now < this.scope.timeline.start || now > this.scope.timeline.end) {
        this.logAccess('validate_target', target, user, false, 'Engagement not active');
        return false;
      }

      // Normalize target for validation
      const normalizedTarget = this.normalizeTarget(target);
      
      // Check exclusions first
      if (this.isExcluded(normalizedTarget)) {
        this.logAccess('validate_target', target, user, false, 'Target in exclusion list');
        return false;
      }

      // Check if target matches approved domains
      if (this.isDomainInScope(normalizedTarget)) {
        this.logAccess('validate_target', target, user, true);
        return true;
      }

      // Check if target matches approved IP ranges
      if (this.isIpInScope(normalizedTarget)) {
        this.logAccess('validate_target', target, user, true);
        return true;
      }

      this.logAccess('validate_target', target, user, false, 'Target not in approved scope');
      return false;

    } catch (error) {
      this.logAccess('validate_target', target, user, false, `Validation error: ${error}`);
      return false;
    }
  }

  /**
   * Check if a specific testing permission is granted
   */
  hasPermission(permission: keyof EngagementScope['permissions']): boolean {
    return this.scope.permissions[permission] || false;
  }

  /**
   * Get the current engagement scope
   */
  getScope(): EngagementScope {
    return { ...this.scope };
  }

  /**
   * Get audit log entries
   */
  getAuditLog(): typeof this.auditLog {
    return [...this.auditLog];
  }

  /**
   * Export audit log to JSON
   */
  exportAuditLog(): string {
    return JSON.stringify({
      engagement: {
        id: this.scope.id,
        name: this.scope.name
      },
      exportedAt: new Date().toISOString(),
      entries: this.auditLog
    }, null, 2);
  }

  private normalizeTarget(target: string): string {
    // Remove protocol prefixes
    target = target.replace(/^https?:\/\//, '');
    target = target.replace(/^ftp:\/\//, '');
    
    // Remove path and query parameters for domain validation
    target = target.split('/')[0];
    target = target.split('?')[0];
    
    // Remove port numbers for domain validation
    target = target.split(':')[0];
    
    return target.toLowerCase();
  }

  private isDomainInScope(target: string): boolean {
    // Check exact domain matches
    if (this.scope.domains.includes(target)) {
      return true;
    }

    // Check subdomain matches
    for (const domain of this.scope.domains) {
      if (target.endsWith('.' + domain)) {
        return true;
      }
    }

    return false;
  }

  private isIpInScope(target: string): boolean {
    // Simple IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(target)) {
      return false;
    }

    const targetIp = this.ipToNumber(target);
    if (targetIp === null) {
      return false;
    }

    // Check each IP range
    for (const range of this.scope.ipRanges) {
      if (this.isIpInRange(targetIp, range)) {
        return true;
      }
    }

    return false;
  }

  private isExcluded(target: string): boolean {
    // Check exact exclusions
    if (this.scope.exclusions.includes(target)) {
      return true;
    }

    // Check if target falls within excluded IP ranges
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(target)) {
      const targetIp = this.ipToNumber(target);
      if (targetIp !== null) {
        for (const exclusion of this.scope.exclusions) {
          if (exclusion.includes('/') && this.isIpInRange(targetIp, exclusion)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(part => part < 0 || part > 255 || isNaN(part))) {
      return null;
    }
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  }

  private isIpInRange(ip: number, cidr: string): boolean {
    const [rangeIp, prefixLength] = cidr.split('/');
    const rangeIpNumber = this.ipToNumber(rangeIp);
    
    if (rangeIpNumber === null || !prefixLength) {
      return false;
    }

    const prefix = parseInt(prefixLength, 10);
    if (prefix < 0 || prefix > 32) {
      return false;
    }

    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    return (ip & mask) === (rangeIpNumber & mask);
  }

  private logAccess(action: string, target: string, user: string, allowed: boolean, reason?: string): void {
    this.auditLog.push({
      timestamp: new Date(),
      action,
      target,
      user,
      allowed,
      reason
    });

    // Keep audit log size manageable (last 10000 entries)
    if (this.auditLog.length > 10000) {
      this.auditLog = this.auditLog.slice(-10000);
    }
  }
}