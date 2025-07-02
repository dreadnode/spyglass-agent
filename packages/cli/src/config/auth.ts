/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { AuthType } from '@dreadnode/spyglass-agent-core';
import { loadEnvironment } from './config.js';

export const validateAuthMethod = (authMethod: string): string | null => {
  loadEnvironment();
  if (authMethod === AuthType.LOGIN_WITH_GOOGLE) {
    return null;
  }

  if (authMethod === AuthType.USE_GEMINI) {
    // TODO: Support additional model backends beyond Gemini (e.g., OpenAI, Anthropic, etc.)
    if (!process.env.GEMINI_API_KEY) {
      return 'GEMINI_API_KEY environment variable not found. Add that to your .env and try again, no reload needed!';
    }
    return null;
  }

  if (authMethod === AuthType.USE_VERTEX_AI) {
    const hasVertexProjectLocationConfig =
      !!process.env.GOOGLE_CLOUD_PROJECT && !!process.env.GOOGLE_CLOUD_LOCATION;
    const hasGoogleApiKey = !!process.env.GOOGLE_API_KEY;
    if (!hasVertexProjectLocationConfig && !hasGoogleApiKey) {
      return (
        'Must specify GOOGLE_GENAI_USE_VERTEXAI=true and either:\n' +
        '• GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION environment variables.\n' +
        '• GOOGLE_API_KEY environment variable (if using express mode).\n' +
        'Update your .env and try again, no reload needed!'
      );
    }
    return null;
  }

  if (authMethod === AuthType.USE_OLLAMA) {
    // Ollama doesn't need API keys, just needs to be running
    // We could add a health check here, but for now just allow it
    console.log('Using Ollama backend - no API key validation required');
    return null;
  }

  if (authMethod === AuthType.USE_OPENAI) {
    if (!process.env.OPENAI_API_KEY) {
      return 'OPENAI_API_KEY environment variable not found. Add that to your .env and try again, no reload needed!';
    }
    return null;
  }

  if (authMethod === AuthType.USE_ANTHROPIC) {
    if (!process.env.ANTHROPIC_API_KEY) {
      return 'ANTHROPIC_API_KEY environment variable not found. Add that to your .env and try again, no reload needed!';
    }
    return null;
  }

  return 'Invalid auth method selected.';
};
