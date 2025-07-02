/**
 * Base class for all red team tools
 * 
 * Provides common functionality for scope validation, audit logging,
 * and integration with the Spyglass Agent tool system.
 */

import { ScopeValidator } from './ScopeValidator.js';
import { EngagementScope, ToolExecutionContext, ToolExecutionResult } from '../types/index.js';

export abstract class RedTeamTool {
  protected scopeValidator: ScopeValidator;
  protected context: ToolExecutionContext;

  constructor(context: ToolExecutionContext) {
    this.context = context;
    this.scopeValidator = new ScopeValidator(context.scope);
  }

  /**
   * Execute the tool with the given parameters
   * This method handles scope validation and audit logging automatically
   */
  async execute(params: any): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    
    try {
      // Pre-execution validation
      await this.validateExecution(params);
      
      // Log tool execution start
      this.context.logger('info', `Starting ${this.getToolName()} execution`, {
        user: this.context.user,
        sessionId: this.context.sessionId,
        params: this.sanitizeParamsForLogging(params)
      });

      // Execute the actual tool logic
      const result = await this.executeImpl(params);

      // Post-execution processing
      const finalResult = await this.postProcess(result);

      // Log successful completion
      const executionTime = Date.now() - startTime;
      this.context.logger('info', `${this.getToolName()} execution completed`, {
        success: finalResult.success,
        executionTime,
        findingCount: finalResult.findings?.length || 0
      });

      return {
        ...finalResult,
        metrics: {
          executionTime,
          requestCount: finalResult.metrics?.requestCount || 0,
          dataSize: finalResult.metrics?.dataSize || 0
        }
      };

    } catch (error) {
      const executionTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      this.context.logger('error', `${this.getToolName()} execution failed`, {
        error: errorMessage,
        executionTime,
        params: this.sanitizeParamsForLogging(params)
      });

      return {
        success: false,
        error: errorMessage,
        metrics: {
          executionTime,
          requestCount: 0,
          dataSize: 0
        }
      };
    }
  }

  /**
   * Validate that the execution is within scope and permitted
   */
  protected async validateExecution(params: any): Promise<void> {
    // Check if tool requires specific permissions
    const requiredPermissions = this.getRequiredPermissions();
    for (const permission of requiredPermissions) {
      if (!this.scopeValidator.hasPermission(permission)) {
        throw new Error(`Tool requires '${permission}' permission which is not granted for this engagement`);
      }
    }

    // Validate targets are in scope
    const targets = this.extractTargets(params);
    for (const target of targets) {
      const isValid = await this.scopeValidator.validateTarget(target, this.context.user);
      if (!isValid) {
        throw new Error(`Target '${target}' is not within the approved engagement scope`);
      }
    }
  }

  /**
   * Post-process results to ensure findings are properly categorized
   */
  protected async postProcess(result: ToolExecutionResult): Promise<ToolExecutionResult> {
    if (result.findings) {
      // Ensure all findings have required fields
      result.findings = result.findings.map(finding => ({
        ...finding,
        discoveredAt: finding.discoveredAt || new Date(),
        discoveredBy: finding.discoveredBy || this.getToolName(),
        status: finding.status || 'new'
      }));
    }

    return result;
  }

  /**
   * Sanitize parameters for logging (remove sensitive data)
   */
  protected sanitizeParamsForLogging(params: any): any {
    const sensitiveKeys = ['password', 'apikey', 'token', 'secret', 'key'];
    const sanitized = { ...params };

    const sanitizeObject = (obj: any): any => {
      if (typeof obj !== 'object' || obj === null) {
        return obj;
      }

      const result: any = Array.isArray(obj) ? [] : {};
      
      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
          result[key] = '[REDACTED]';
        } else if (typeof value === 'object') {
          result[key] = sanitizeObject(value);
        } else {
          result[key] = value;
        }
      }

      return result;
    };

    return sanitizeObject(sanitized);
  }

  // Abstract methods that must be implemented by concrete tools

  /**
   * Get the name of this tool for logging and identification
   */
  abstract getToolName(): string;

  /**
   * Get the permissions required by this tool
   */
  abstract getRequiredPermissions(): Array<keyof EngagementScope['permissions']>;

  /**
   * Extract targets from the tool parameters for scope validation
   */
  abstract extractTargets(params: any): string[];

  /**
   * Implement the actual tool logic
   */
  protected abstract executeImpl(params: any): Promise<ToolExecutionResult>;

  /**
   * Get the JSON schema for this tool's parameters
   */
  abstract getParameterSchema(): object;

  /**
   * Get a description of what this tool does
   */
  abstract getDescription(): string;
}