/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  CountTokensResponse,
  GenerateContentResponse,
  GenerateContentParameters,
  CountTokensParameters,
  EmbedContentResponse,
  EmbedContentParameters,
  GoogleGenAI,
} from '@google/genai';
import { createCodeAssistContentGenerator } from '../code_assist/codeAssist.js';
import { createOllamaContentGenerator } from '../ollama/ollamaContentGenerator.js';
import { OpenAIContentGenerator } from '../openai/openaiContentGenerator.js';
import { AnthropicContentGenerator } from '../anthropic/anthropicContentGenerator.js';
import { DEFAULT_GEMINI_MODEL, DEFAULT_OLLAMA_MODEL } from '../config/models.js';
import { getEffectiveModel } from './modelCheck.js';

/**
 * Interface abstracting the core functionalities for generating content and counting tokens.
 */
export interface ContentGenerator {
  generateContent(
    request: GenerateContentParameters,
  ): Promise<GenerateContentResponse>;

  generateContentStream(
    request: GenerateContentParameters,
  ): Promise<AsyncGenerator<GenerateContentResponse>>;

  countTokens(request: CountTokensParameters): Promise<CountTokensResponse>;

  embedContent(request: EmbedContentParameters): Promise<EmbedContentResponse>;
}

export enum AuthType {
  LOGIN_WITH_GOOGLE = 'oauth-personal',
  USE_GEMINI = 'gemini-api-key',
  USE_VERTEX_AI = 'vertex-ai',
  USE_OLLAMA = 'ollama',
  USE_OPENAI = 'openai',
  USE_ANTHROPIC = 'anthropic',
}

export type ContentGeneratorConfig = {
  model: string;
  apiKey?: string;
  vertexai?: boolean;
  authType?: AuthType | undefined;
  ollamaUrl?: string;
  baseUrl?: string;
  customHeaders?: Record<string, string>;
  timeout?: number;
};

export async function createContentGeneratorConfig(
  model: string | undefined,
  authType: AuthType | undefined,
  config?: { getModel?: () => string },
): Promise<ContentGeneratorConfig> {
  const geminiApiKey = process.env.GEMINI_API_KEY;
  const googleApiKey = process.env.GOOGLE_API_KEY;
  const googleCloudProject = process.env.GOOGLE_CLOUD_PROJECT;
  const googleCloudLocation = process.env.GOOGLE_CLOUD_LOCATION;
  const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';

  // Use runtime model from config if available, otherwise fallback to parameter or default
  const effectiveModel = config?.getModel?.() || model || DEFAULT_GEMINI_MODEL;

  const contentGeneratorConfig: ContentGeneratorConfig = {
    model: effectiveModel,
    authType,
  };

  // if we are using google auth nothing else to validate for now
  if (authType === AuthType.LOGIN_WITH_GOOGLE) {
    return contentGeneratorConfig;
  }

  if (authType === AuthType.USE_GEMINI && geminiApiKey) {
    contentGeneratorConfig.apiKey = geminiApiKey;
    contentGeneratorConfig.model = await getEffectiveModel(
      contentGeneratorConfig.apiKey,
      contentGeneratorConfig.model,
    );

    return contentGeneratorConfig;
  }

  if (
    authType === AuthType.USE_VERTEX_AI &&
    !!googleApiKey &&
    googleCloudProject &&
    googleCloudLocation
  ) {
    contentGeneratorConfig.apiKey = googleApiKey;
    contentGeneratorConfig.vertexai = true;
    contentGeneratorConfig.model = await getEffectiveModel(
      contentGeneratorConfig.apiKey,
      contentGeneratorConfig.model,
    );

    return contentGeneratorConfig;
  }

  if (authType === AuthType.USE_OLLAMA) {
    contentGeneratorConfig.ollamaUrl = ollamaUrl;
    // Default to llama3.1 if no model specified for Ollama
    if (effectiveModel === DEFAULT_GEMINI_MODEL) {
      contentGeneratorConfig.model = DEFAULT_OLLAMA_MODEL;
    }
    return contentGeneratorConfig;
  }

  if (authType === AuthType.USE_OPENAI) {
    const openaiApiKey = process.env.OPENAI_API_KEY;
    if (!openaiApiKey) {
      throw new Error('OPENAI_API_KEY environment variable is required for OpenAI backend');
    }
    contentGeneratorConfig.apiKey = openaiApiKey;
    // Default to gpt-4 if no model specified for OpenAI
    if (effectiveModel === DEFAULT_GEMINI_MODEL) {
      contentGeneratorConfig.model = 'gpt-4';
    }
    return contentGeneratorConfig;
  }

  if (authType === AuthType.USE_ANTHROPIC) {
    const anthropicApiKey = process.env.ANTHROPIC_API_KEY;
    if (!anthropicApiKey) {
      throw new Error('ANTHROPIC_API_KEY environment variable is required for Anthropic backend');
    }
    contentGeneratorConfig.apiKey = anthropicApiKey;
    // Default to Claude-3.5 Sonnet if no model specified for Anthropic
    if (effectiveModel === DEFAULT_GEMINI_MODEL) {
      contentGeneratorConfig.model = 'claude-3-5-sonnet-20241022';
    }
    return contentGeneratorConfig;
  }

  return contentGeneratorConfig;
}

export async function createContentGenerator(
  config: ContentGeneratorConfig,
  sessionId?: string,
): Promise<ContentGenerator> {
  const version = process.env.CLI_VERSION || process.version;
  const httpOptions = {
    headers: {
      'User-Agent': `SpyglassAgent/${version} (${process.platform}; ${process.arch})`,
    },
  };
  if (config.authType === AuthType.LOGIN_WITH_GOOGLE) {
    return createCodeAssistContentGenerator(
      httpOptions,
      config.authType,
      sessionId,
    );
  }

  if (
    config.authType === AuthType.USE_GEMINI ||
    config.authType === AuthType.USE_VERTEX_AI
  ) {
    const googleGenAI = new GoogleGenAI({
      apiKey: config.apiKey === '' ? undefined : config.apiKey,
      vertexai: config.vertexai,
      httpOptions,
    });

    return googleGenAI.models;
  }

  if (config.authType === AuthType.USE_OLLAMA) {
    return createOllamaContentGenerator(config);
  }

  if (config.authType === AuthType.USE_OPENAI) {
    return new OpenAIContentGenerator(config);
  }

  if (config.authType === AuthType.USE_ANTHROPIC) {
    return new AnthropicContentGenerator(config);
  }

  throw new Error(
    `Error creating contentGenerator: Unsupported authType: ${config.authType}`,
  );
}
