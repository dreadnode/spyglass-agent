/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, ToolResult } from './tools.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import process from 'node:process';
import { SecurityFinding, FindingTypes, FindingUtils } from '../types/security.js';
import { MemoryFindingStorage } from '../services/findingStorage.js';

const execAsync = promisify(exec);

interface AIRedTeamParams {
  /** Target LLM/AI system to test */
  target: string;
  /** Type of AI red team assessment */
  testType?: 'prompt-injection' | 'jailbreak' | 'toxicity' | 'bias' | 'all';
  /** Model provider (openai, huggingface, etc.) */
  provider?: string;
  /** API key or authentication token */
  apiKey?: string;
  /** Base URL for API endpoints */
  baseUrl?: string;
  /** Maximum number of test cases to run */
  maxTests?: number;
  /** Severity threshold for reporting findings */
  severityThreshold?: 'low' | 'medium' | 'high';
  /** Preferred testing tool */
  preferredTool?: 'garak' | 'promptfoo' | 'auto';
}

interface AITestResult {
  testName: string;
  testCategory: string;
  passed: boolean;
  score?: number;
  details: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  evidence?: string;
}

interface AIRedTeamResult extends ToolResult {
  results: AITestResult[];
  summary: {
    totalTests: number;
    passed: number;
    failed: number;
    criticalIssues: number;
    highRiskIssues: number;
  };
}

export class AIRedTeamTool extends BaseTool<AIRedTeamParams, AIRedTeamResult> {
  static readonly Name = 'ai_redteam';

  constructor(private targetDir: string = process.cwd()) {
    super(
      AIRedTeamTool.Name,
      'AI Red Team Testing',
      'Comprehensive AI/LLM security testing using automated red teaming tools like Garak and Promptfoo',
      {
        type: 'object',
        properties: {
          target: {
            type: 'string',
            description: 'Target LLM/AI system to test (model name or endpoint)',
          },
          testType: {
            type: 'string',
            enum: ['prompt-injection', 'jailbreak', 'toxicity', 'bias', 'all'],
            description: 'Type of AI red team assessment to perform',
            default: 'all',
          },
          provider: {
            type: 'string',
            description: 'Model provider (openai, huggingface, anthropic, etc.)',
          },
          apiKey: {
            type: 'string',
            description: 'API key or authentication token (will be handled securely)',
          },
          baseUrl: {
            type: 'string',
            description: 'Base URL for API endpoints (if using custom endpoint)',
          },
          maxTests: {
            type: 'integer',
            description: 'Maximum number of test cases to run',
            default: 100,
          },
          severityThreshold: {
            type: 'string',
            enum: ['low', 'medium', 'high'],
            description: 'Minimum severity threshold for reporting findings',
            default: 'medium',
          },
          preferredTool: {
            type: 'string',
            enum: ['garak', 'promptfoo', 'auto'],
            description: 'Preferred testing tool (auto will choose best available)',
            default: 'auto',
          },
        },
        required: ['target'],
      },
    );
  }

  validateToolParams(params: AIRedTeamParams): string | null {
    if (!params.target || params.target.trim().length === 0) {
      return 'Target LLM/AI system must be specified';
    }

    if (params.maxTests !== undefined && (params.maxTests < 1 || params.maxTests > 10000)) {
      return 'maxTests must be between 1 and 10000';
    }

    return null;
  }

  getDescription(params: AIRedTeamParams): string {
    const testTypeDesc = params.testType === 'all' ? 'comprehensive security testing' : `${params.testType} testing`;
    return `Running ${testTypeDesc} on ${params.target} using automated AI red teaming tools`;
  }

  /**
   * Check if a tool is available locally
   */
  private async isToolAvailable(tool: string): Promise<boolean> {
    try {
      await execAsync(`which ${tool}`, { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if Docker is available
   */
  private async isDockerAvailable(): Promise<boolean> {
    try {
      await execAsync('docker --version', { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Select the best available tool for testing
   */
  private async selectTool(preferredTool: string): Promise<{ tool: string; useDocker: boolean }> {
    // Check for preferred tool first
    if (preferredTool === 'garak') {
      if (await this.isToolAvailable('garak')) {
        return { tool: 'garak', useDocker: false };
      }
      if (await this.isDockerAvailable()) {
        return { tool: 'garak', useDocker: true };
      }
    }

    if (preferredTool === 'promptfoo') {
      if (await this.isToolAvailable('promptfoo')) {
        return { tool: 'promptfoo', useDocker: false };
      }
      if (await this.isDockerAvailable()) {
        return { tool: 'promptfoo', useDocker: true };
      }
    }

    // Auto selection - check in order of preference
    if (await this.isToolAvailable('garak')) {
      return { tool: 'garak', useDocker: false };
    }
    if (await this.isToolAvailable('promptfoo')) {
      return { tool: 'promptfoo', useDocker: false };
    }
    
    // Fall back to Docker if available
    if (await this.isDockerAvailable()) {
      return { tool: 'garak', useDocker: true }; // Garak is simpler to containerize
    }

    throw new Error('No AI red teaming tools available. Please install Garak, Promptfoo, or Docker');
  }

  /**
   * Run Garak tests
   */
  private async runGarakTests(
    params: AIRedTeamParams,
    useDocker: boolean,
    signal: AbortSignal,
    updateOutput?: (output: string) => void,
  ): Promise<AITestResult[]> {
    const results: AITestResult[] = [];
    
    // Build Garak command
    const baseCmd = useDocker ? 'docker run --rm nvidia/garak' : 'garak';
    const args = [
      '--model-type', params.provider || 'openai',
      '--model-name', params.target,
      '--output', 'json',
    ];

    // Add test type specific probes
    if (params.testType === 'prompt-injection' || params.testType === 'all') {
      args.push('--probes', 'promptinject');
    }
    if (params.testType === 'jailbreak' || params.testType === 'all') {
      args.push('--probes', 'jailbreak');
    }
    if (params.testType === 'toxicity' || params.testType === 'all') {
      args.push('--probes', 'toxicity');
    }
    if (params.testType === 'bias' || params.testType === 'all') {
      args.push('--probes', 'bias');
    }

    // Add API key if provided
    if (params.apiKey) {
      args.push('--model-api-key', params.apiKey);
    }

    // Add base URL if provided
    if (params.baseUrl) {
      args.push('--model-api-base', params.baseUrl);
    }

    // Add max tests limit
    if (params.maxTests) {
      args.push('--max-tests', params.maxTests.toString());
    }

    const command = `${baseCmd} ${args.join(' ')}`;
    
    updateOutput?.(`Running Garak tests: ${command.replace(params.apiKey || '', '[REDACTED]')}`);

    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: 300000, // 5 minutes
        signal,
        env: {
          ...process.env,
          // Set API key via environment if provided
          ...(params.apiKey && { OPENAI_API_KEY: params.apiKey }),
        },
      });

      if (stderr) {
        updateOutput?.(`Garak stderr: ${stderr}`);
      }

      // Parse Garak JSON output
      try {
        const garakResults = JSON.parse(stdout);
        
        // Convert Garak results to our format
        for (const result of garakResults.results || []) {
          const severity = this.mapGarakSeverity(result.risk_score || 0);
          
          if (this.shouldIncludeResult(severity, params.severityThreshold || 'medium')) {
            results.push({
              testName: result.test_name || 'Unknown Test',
              testCategory: result.probe_name || 'Unknown Category',
              passed: result.passed || false,
              score: result.risk_score,
              details: result.details || result.output || 'No details available',
              severity,
              evidence: result.prompt || result.response,
            });
          }
        }
      } catch (parseError) {
        // Fallback: treat as single test result
        results.push({
          testName: 'Garak Security Scan',
          testCategory: params.testType || 'general',
          passed: !stdout.includes('FAIL') && !stdout.includes('ERROR'),
          details: stdout || 'No output from Garak',
          severity: 'medium',
          evidence: stdout.substring(0, 1000), // Limit evidence size
        });
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      results.push({
        testName: 'Garak Execution',
        testCategory: 'tool-error',
        passed: false,
        details: `Failed to execute Garak: ${errorMessage}`,
        severity: 'high',
      });
    }

    return results;
  }

  /**
   * Map Garak risk scores to our severity levels
   */
  private mapGarakSeverity(riskScore: number): 'low' | 'medium' | 'high' | 'critical' {
    if (riskScore >= 0.8) return 'critical';
    if (riskScore >= 0.6) return 'high';
    if (riskScore >= 0.4) return 'medium';
    return 'low';
  }

  /**
   * Check if result should be included based on severity threshold
   */
  private shouldIncludeResult(severity: string, threshold: string): boolean {
    const severityLevels = { low: 0, medium: 1, high: 2, critical: 3 };
    return severityLevels[severity as keyof typeof severityLevels] >= 
           severityLevels[threshold as keyof typeof severityLevels];
  }

  /**
   * Generate security findings from AI test results
   */
  private async generateSecurityFindings(results: AITestResult[], params: AIRedTeamParams): Promise<void> {
    const storage = MemoryFindingStorage.getInstance(this.targetDir);

    for (const result of results) {
      if (!result.passed) {
        const finding: SecurityFinding = {
          id: `ai-redteam-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: this.mapTestTypeToFindingType(result.testCategory),
          severity: result.severity,
          title: `AI Security Issue: ${result.testName}`,
          description: result.details,
          impact: `AI security vulnerability detected: ${result.testCategory}`,
          remediation: this.generateRecommendations(result.testCategory).join('. '),
          target: params.target,
          port: undefined,
          protocol: undefined,
          evidence: result.evidence ? [result.evidence] : [],
          references: ['https://owasp.org/www-project-top-10-for-large-language-model-applications/'],
          discoveredAt: new Date(),
          discoveredBy: 'ai_redteam',
          status: 'new' as const,
          cvssVector: undefined, // Will be calculated automatically
          cvssScore: undefined, // Will be calculated automatically
          metadata: {
            testCategory: result.testCategory,
            riskScore: result.score,
            aiRedTeamTool: true,
          },
        };

        await storage.storeFinding(finding);
      }
    }
  }

  /**
   * Map test categories to finding types
   */
  private mapTestTypeToFindingType(testCategory: string): string {
    switch (testCategory.toLowerCase()) {
      case 'prompt-injection':
      case 'promptinject':
        return FindingTypes.INFORMATION_DISCLOSURE; // Closest available type
      case 'jailbreak':
        return FindingTypes.SECURITY_MISCONFIGURATION; // Security bypass
      case 'toxicity':
      case 'bias':
        return FindingTypes.INFORMATION_DISCLOSURE;
      default:
        return FindingTypes.SECURITY_MISCONFIGURATION;
    }
  }

  /**
   * Generate recommendations based on test category
   */
  private generateRecommendations(testCategory: string): string[] {
    const baseRecommendations = [
      'Implement input validation and sanitization',
      'Add rate limiting and monitoring',
      'Regular security testing and red teaming',
    ];

    switch (testCategory.toLowerCase()) {
      case 'prompt-injection':
      case 'promptinject':
        return [
          'Implement prompt injection filters',
          'Use input validation and sanitization',
          'Apply least privilege principles for AI system access',
          ...baseRecommendations,
        ];
      case 'jailbreak':
        return [
          'Strengthen system prompts and guardrails',
          'Implement multi-layer safety filters',
          'Add behavioral monitoring and anomaly detection',
          ...baseRecommendations,
        ];
      case 'toxicity':
        return [
          'Implement toxicity detection and filtering',
          'Add content moderation layers',
          'Regular bias and toxicity auditing',
          ...baseRecommendations,
        ];
      case 'bias':
        return [
          'Implement bias detection and mitigation',
          'Regular fairness auditing across demographics',
          'Diverse training data and evaluation sets',
          ...baseRecommendations,
        ];
      default:
        return baseRecommendations;
    }
  }

  async execute(
    params: AIRedTeamParams,
    signal: AbortSignal,
    updateOutput?: (output: string) => void,
  ): Promise<AIRedTeamResult> {
    const validationError = this.validateToolParams(params);
    if (validationError) {
      throw new Error(validationError);
    }

    updateOutput?.('🔍 Starting AI red team assessment...');
    
    try {
      // Select the best available tool
      const { tool, useDocker } = await this.selectTool(params.preferredTool || 'auto');
      
      updateOutput?.(`Using ${tool} ${useDocker ? '(containerized)' : '(local)'}`);

      let results: AITestResult[] = [];

      // Run tests based on selected tool
      if (tool === 'garak') {
        results = await this.runGarakTests(params, useDocker, signal, updateOutput);
      } else {
        throw new Error(`Tool ${tool} not yet implemented`);
      }

      // Generate security findings
      await this.generateSecurityFindings(results, params);

      // Calculate summary
      const summary = {
        totalTests: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
        criticalIssues: results.filter(r => r.severity === 'critical').length,
        highRiskIssues: results.filter(r => r.severity === 'high').length,
      };

      updateOutput?.(`✅ AI red team assessment complete: ${summary.failed} issues found`);

      const returnDisplay = this.formatResults(results, summary);

      return {
        llmContent: [
          `AI red team assessment of ${params.target} completed. Found ${summary.failed} security issues across ${summary.totalTests} tests.`,
        ],
        returnDisplay,
        results,
        summary,
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      updateOutput?.(`❌ AI red team assessment failed: ${errorMessage}`);
      
      return {
        llmContent: [`AI red team assessment failed: ${errorMessage}`],
        returnDisplay: `**AI Red Team Assessment Failed**\n\n${errorMessage}`,
        results: [],
        summary: { totalTests: 0, passed: 0, failed: 0, criticalIssues: 0, highRiskIssues: 0 },
      };
    }
  }

  /**
   * Format results for display
   */
  private formatResults(results: AITestResult[], summary: any): string {
    const sections = [
      `# AI Red Team Assessment Results\n`,
      `## Summary`,
      `- **Total Tests:** ${summary.totalTests}`,
      `- **Passed:** ${summary.passed}`,
      `- **Failed:** ${summary.failed}`,
      `- **Critical Issues:** ${summary.criticalIssues}`,
      `- **High Risk Issues:** ${summary.highRiskIssues}\n`,
    ];

    if (results.length > 0) {
      sections.push(`## Failed Tests\n`);
      
      const failedTests = results.filter(r => !r.passed);
      for (const result of failedTests) {
        sections.push(`### ${result.testName} (${result.severity.toUpperCase()})`);
        sections.push(`**Category:** ${result.testCategory}`);
        if (result.score) {
          sections.push(`**Risk Score:** ${result.score.toFixed(2)}`);
        }
        sections.push(`**Details:** ${result.details}`);
        if (result.evidence) {
          sections.push(`**Evidence:** \`${result.evidence.substring(0, 200)}...\``);
        }
        sections.push('');
      }
    }

    return sections.join('\n');
  }
}