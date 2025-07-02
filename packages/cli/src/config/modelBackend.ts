/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { AuthType } from '@dreadnode/spyglass-agent-core';

/**
 * Utility functions for managing model backend selection
 */

export function getDefaultAuthTypeFromEnv(): AuthType | undefined {
  // Check environment variable for preferred backend
  const preferredBackend = process.env.SPYGLASS_MODEL_BACKEND?.toLowerCase();
  
  switch (preferredBackend) {
    case 'ollama':
    case 'local':
      return AuthType.USE_OLLAMA;
    case 'gemini':
    case 'google':
      return AuthType.USE_GEMINI;
    case 'vertex':
    case 'vertexai':
      return AuthType.USE_VERTEX_AI;
    case 'oauth':
    case 'google-oauth':
      return AuthType.LOGIN_WITH_GOOGLE;
    case 'openai':
    case 'gpt':
      return AuthType.USE_OPENAI;
    case 'anthropic':
    case 'claude':
      return AuthType.USE_ANTHROPIC;
    default:
      // Auto-detect based on available credentials
      return autoDetectAuthType();
  }
}

function autoDetectAuthType(): AuthType | undefined {
  // Priority order: OpenAI/Anthropic (cloud), Gemini API, Vertex AI, then Ollama (local)
  
  // Check for cloud AI APIs first (usually more reliable than local)
  if (process.env.OPENAI_API_KEY) {
    return AuthType.USE_OPENAI;
  }
  
  if (process.env.ANTHROPIC_API_KEY) {
    return AuthType.USE_ANTHROPIC;
  }
  
  if (process.env.GEMINI_API_KEY) {
    return AuthType.USE_GEMINI;
  }
  
  if (process.env.GOOGLE_API_KEY && 
      process.env.GOOGLE_CLOUD_PROJECT && 
      process.env.GOOGLE_CLOUD_LOCATION) {
    return AuthType.USE_VERTEX_AI;
  }
  
  // Default to Ollama if no API keys found (user can install/start Ollama)
  return AuthType.USE_OLLAMA;
}

export function getModelBackendDisplayName(authType: AuthType): string {
  switch (authType) {
    case AuthType.USE_OLLAMA:
      return 'Ollama (Local)';
    case AuthType.USE_GEMINI:
      return 'Google Gemini API';
    case AuthType.USE_VERTEX_AI:
      return 'Google Vertex AI';
    case AuthType.LOGIN_WITH_GOOGLE:
      return 'Google OAuth';
    case AuthType.USE_OPENAI:
      return 'OpenAI API';
    case AuthType.USE_ANTHROPIC:
      return 'Anthropic Claude API';
    default:
      return 'Unknown';
  }
}

export function getModelBackendInstructions(authType: AuthType): string {
  switch (authType) {
    case AuthType.USE_OLLAMA:
      return `To use Ollama:
1. Install Ollama: https://ollama.ai
2. Start Ollama: \`ollama serve\`
3. Pull a model: \`ollama pull llama3.1\`
4. Set model (optional): \`export SPYGLASS_MODEL_BACKEND=ollama\``;
    
    case AuthType.USE_GEMINI:
      return `To use Gemini API:
1. Get API key: https://aistudio.google.com/app/apikey
2. Set environment variable: \`export GEMINI_API_KEY=your_key_here\`
3. Set backend: \`export SPYGLASS_MODEL_BACKEND=gemini\``;
    
    case AuthType.USE_VERTEX_AI:
      return `To use Vertex AI:
1. Set up Google Cloud project
2. Set environment variables:
   \`export GOOGLE_API_KEY=your_key\`
   \`export GOOGLE_CLOUD_PROJECT=your_project\`
   \`export GOOGLE_CLOUD_LOCATION=us-central1\`
3. Set backend: \`export SPYGLASS_MODEL_BACKEND=vertex\``;
    
    case AuthType.LOGIN_WITH_GOOGLE:
      return `To use Google OAuth:
1. No setup required
2. Set backend: \`export SPYGLASS_MODEL_BACKEND=oauth\`
3. Follow login prompts`;
    
    case AuthType.USE_OPENAI:
      return `To use OpenAI API:
1. Get API key: https://platform.openai.com/api-keys
2. Set environment variable: \`export OPENAI_API_KEY=your_key_here\`
3. Set backend: \`export SPYGLASS_MODEL_BACKEND=openai\`
4. Optional: Set model: \`export SPYGLASS_MODEL=gpt-4o\``;
    
    case AuthType.USE_ANTHROPIC:
      return `To use Anthropic Claude API:
1. Get API key: https://console.anthropic.com/account/keys
2. Set environment variable: \`export ANTHROPIC_API_KEY=your_key_here\`
3. Set backend: \`export SPYGLASS_MODEL_BACKEND=anthropic\`
4. Optional: Set model: \`export SPYGLASS_MODEL=claude-3-5-sonnet-20241022\``;
    
    default:
      return 'Unknown backend';
  }
}