/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { exec } from 'child_process';
import { AIRedTeamTool } from './ai-redteam.js';

// Mock the exec function
vi.mock('child_process', () => ({
  exec: vi.fn(),
}));
const mockExec = exec as any;

describe('AIRedTeamTool', () => {
  let tool: AIRedTeamTool;
  let mockController: AbortController;

  beforeEach(() => {
    tool = new AIRedTeamTool();
    mockController = new AbortController();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('validateToolParams', () => {
    it('should return error for empty target', () => {
      const params = { target: '' };
      const result = tool.validateToolParams(params);
      expect(result).toBe('Target LLM/AI system must be specified');
    });

    it('should return error for invalid maxTests', () => {
      const params = { target: 'gpt-3.5-turbo', maxTests: 0 };
      const result = tool.validateToolParams(params);
      expect(result).toBe('maxTests must be between 1 and 10000');
    });

    it('should return null for valid params', () => {
      const params = { target: 'gpt-3.5-turbo' };
      const result = tool.validateToolParams(params);
      expect(result).toBeNull();
    });
  });

  describe('getDescription', () => {
    it('should return appropriate description', () => {
      const params = { target: 'gpt-3.5-turbo', testType: 'prompt-injection' as const };
      const result = tool.getDescription(params);
      expect(result).toBe('Running prompt-injection testing on gpt-3.5-turbo using automated AI red teaming tools');
    });

    it('should handle "all" test type', () => {
      const params = { target: 'claude-3', testType: 'all' as const };
      const result = tool.getDescription(params);
      expect(result).toBe('Running comprehensive security testing on claude-3 using automated AI red teaming tools');
    });
  });

  describe('tool availability checking', () => {
    it('should check for tool availability', async () => {
      // Mock successful tool check
      mockExec.mockImplementation((command: string, options: any, callback?: any) => {
        const cb = typeof options === 'function' ? options : callback;
        if (cb) {
          cb(null, { stdout: '/usr/local/bin/garak', stderr: '' });
        }
        return {} as any;
      });

      const params = {
        target: 'gpt-3.5-turbo',
        testType: 'prompt-injection' as const,
        preferredTool: 'auto' as const,
      };

      // This should not throw
      const result = await tool.execute(params, mockController.signal);
      expect(result).toBeDefined();
    });

    it('should handle missing tools gracefully', async () => {
      // Mock tool not found
      mockExec.mockImplementation((command: string, options: any, callback?: any) => {
        const cb = typeof options === 'function' ? options : callback;
        if (cb) {
          const error = new Error('Command not found') as any;
          error.code = 127;
          cb(error, null);
        }
        return {} as any;
      });

      const params = {
        target: 'gpt-3.5-turbo',
        testType: 'prompt-injection' as const,
      };

      const result = await tool.execute(params, mockController.signal);
      expect(result.summary.totalTests).toBe(0);
      expect(result.summary.failed).toBe(0);
    });
  });

  describe('tool metadata', () => {
    it('should have correct name', () => {
      expect(tool.name).toBe('ai_redteam');
      expect(AIRedTeamTool.Name).toBe('ai_redteam');
    });

    it('should have appropriate schema', () => {
      expect(tool.schema.name).toBe('ai_redteam');
      expect(tool.schema.description).toContain('AI/LLM security testing');
      expect(tool.schema.parameters).toBeDefined();
    });

    it('should require target parameter', () => {
      const schema = tool.schema.parameters as any;
      expect(schema.required).toContain('target');
    });

    it('should have appropriate parameter constraints', () => {
      const schema = tool.schema.parameters as any;
      const properties = schema.properties;
      
      expect(properties.testType.enum).toContain('prompt-injection');
      expect(properties.testType.enum).toContain('jailbreak');
      expect(properties.testType.enum).toContain('all');
      
      expect(properties.preferredTool.enum).toContain('garak');
      expect(properties.preferredTool.enum).toContain('promptfoo');
      expect(properties.preferredTool.enum).toContain('auto');
    });
  });

  describe('result parsing', () => {
    it('should handle empty Garak results', async () => {
      // Mock Garak execution with empty results
      mockExec.mockImplementation((command: string, options: any, callback?: any) => {
        const cb = typeof options === 'function' ? options : callback;
        if (command.includes('garak')) {
          if (cb) {
            cb(null, { stdout: '{"results": []}', stderr: '' });
          }
        } else {
          // Tool availability check
          if (cb) {
            cb(null, { stdout: '/usr/local/bin/garak', stderr: '' });
          }
        }
        return {} as any;
      });

      const params = {
        target: 'gpt-3.5-turbo',
        testType: 'prompt-injection' as const,
      };

      const result = await tool.execute(params, mockController.signal);
      expect(result.summary.totalTests).toBe(0);
      expect(result.results).toEqual([]);
    });

    it('should handle malformed JSON gracefully', async () => {
      // Mock Garak execution with invalid JSON
      mockExec.mockImplementation((command: string, options: any, callback?: any) => {
        const cb = typeof options === 'function' ? options : callback;
        if (command.includes('garak')) {
          if (cb) {
            cb(null, { stdout: 'invalid json output', stderr: '' });
          }
        } else {
          // Tool availability check  
          if (cb) {
            cb(null, { stdout: '/usr/local/bin/garak', stderr: '' });
          }
        }
        return {} as any;
      });

      const params = {
        target: 'gpt-3.5-turbo',
        testType: 'prompt-injection' as const,
      };

      const result = await tool.execute(params, mockController.signal);
      expect(result.summary.totalTests).toBe(1);
      expect(result.results[0].testName).toBe('Garak Security Scan');
    });
  });
});