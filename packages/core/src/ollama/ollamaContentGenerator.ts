/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  ContentGenerator,
  ContentGeneratorConfig,
} from '../core/contentGenerator.js';
import {
  GenerateContentParameters,
  GenerateContentResponse,
  CountTokensParameters,
  CountTokensResponse,
  EmbedContentParameters,
  EmbedContentResponse,
  Content,
  Part,
  FunctionCall,
  FunctionResponse,
  FinishReason,
} from '@google/genai';

/**
 * Ollama implementation of ContentGenerator that adapts Ollama API
 * to the Google GenAI interface for compatibility with existing code.
 */
export class OllamaContentGenerator implements ContentGenerator {
  private baseUrl: string;
  private model: string;

  constructor(config: ContentGeneratorConfig) {
    this.baseUrl = config.ollamaUrl || 'http://localhost:11434';
    this.model = config.model;
  }

  async generateContent(request: GenerateContentParameters): Promise<GenerateContentResponse> {
    try {
      const ollamaRequest = this.convertToOllamaRequest(request);
      
      const response = await fetch(`${this.baseUrl}/api/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: this.model,
          messages: ollamaRequest.messages,
          stream: false,
          options: {
            temperature: ollamaRequest.temperature,
          }
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
      }

      const ollamaResponse = await response.json();
      return this.convertFromOllamaResponse(ollamaResponse);
    } catch (error) {
      console.error('[ERROR] Ollama API call failed:', error);
      throw error;
    }
  }

  async generateContentStream(request: GenerateContentParameters): Promise<AsyncGenerator<GenerateContentResponse>> {
    const generator = async function* (this: OllamaContentGenerator) {
      try {
        const ollamaRequest = this.convertToOllamaRequest(request);
        
        const response = await fetch(`${this.baseUrl}/api/chat`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: this.model,
            messages: ollamaRequest.messages,
            stream: true,
            options: {
              temperature: ollamaRequest.temperature,
            }
          }),
        });

        if (!response.ok) {
          throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
        }

        const reader = response.body?.getReader();
        if (!reader) {
          throw new Error('Response body is not readable');
        }

        const decoder = new TextDecoder();
        let buffer = '';

        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
              if (line.trim()) {
                try {
                  const chunk = JSON.parse(line);
                  if (chunk.message?.content) {
                    yield this.convertFromOllamaStreamChunk(chunk);
                  }
                  if (chunk.done) {
                    return;
                  }
                } catch (parseError) {
                  console.warn('[WARN] Failed to parse Ollama stream chunk:', parseError);
                }
              }
            }
          }
        } finally {
          reader.releaseLock();
        }
      } catch (error) {
        console.error('[ERROR] Ollama streaming failed:', error);
        throw error;
      }
    }.bind(this);

    return generator();
  }

  async countTokens(request: CountTokensParameters): Promise<CountTokensResponse> {
    // Ollama doesn't have a direct token counting API
    // We'll approximate based on content length
    let content = '';
    
    if (typeof request.contents === 'string') {
      content = request.contents;
    } else if (Array.isArray(request.contents)) {
      content = this.extractTextContent(request.contents as any[]);
    } else if (request.contents) {
      content = this.extractTextContent([request.contents as any]);
    }
    
    const estimatedTokens = Math.ceil(content.length / 4); // Rough approximation: 4 chars per token
    
    return {
      totalTokens: estimatedTokens,
    };
  }

  async embedContent(request: EmbedContentParameters): Promise<EmbedContentResponse> {
    try {
      // Use Ollama's embedding API if available
      const response = await fetch(`${this.baseUrl}/api/embeddings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'nomic-embed-text', // Default embedding model for Ollama
          prompt: typeof request.contents === 'string' ? request.contents : this.extractTextContent([request.contents as any]),
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama embedding API error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      return {
        embeddings: [{
          values: result.embedding || [],
        }],
      };
    } catch (error) {
      console.warn('[WARN] Ollama embedding failed, returning dummy response:', error);
      // Return a dummy embedding if the API fails
      return {
        embeddings: [{
          values: new Array(768).fill(0), // Standard embedding dimension
        }],
      };
    }
  }

  private convertToOllamaRequest(request: GenerateContentParameters): any {
    const messages: any[] = [];
    
    // Convert system instructions (located in config.systemInstruction)
    if (request.config?.systemInstruction) {
      const systemContent = this.extractTextContent([request.config.systemInstruction as any]);
      if (systemContent) {
        messages.push({
          role: 'system',
          content: systemContent,
        });
      }
    }

    // Convert conversation history
    if (request.contents) {
      const contents = Array.isArray(request.contents) ? request.contents : [request.contents];
      for (const content of contents) {
        // Handle different content types
        if (typeof content === 'string') {
          messages.push({
            role: 'user',
            content: content,
          });
        } else if (content && typeof content === 'object' && 'role' in content) {
          const role = content.role === 'model' ? 'assistant' : 'user';
          const textContent = this.extractTextContent([content as any]);
          
          if (textContent) {
            messages.push({
              role,
              content: textContent,
            });
          }
        }
      }
    }

    return {
      messages,
      temperature: request.config?.temperature || 0.7,
    };
  }

  private convertFromOllamaResponse(ollamaResponse: any): GenerateContentResponse {
    const content = ollamaResponse.message?.content || '';
    
    // Create a response object that matches the expected structure
    const response = {
      candidates: [
        {
          content: {
            parts: [{ text: content }],
            role: 'model',
          },
          finishReason: 'STOP' as FinishReason,
          index: 0,
        },
      ],
      usageMetadata: {
        promptTokenCount: 0, // Ollama doesn't provide this
        candidatesTokenCount: 0,
        totalTokenCount: 0,
      },
      // Add the getters that the class would have
      get text() {
        return content;
      },
      get functionCalls() {
        return undefined;
      },
      get executableCode() {
        return undefined;
      },
      get codeExecutionResult() {
        return undefined;
      },
      data: undefined,
    } as GenerateContentResponse;

    return response;
  }

  private convertFromOllamaStreamChunk(chunk: any): GenerateContentResponse {
    const content = chunk.message?.content || '';
    
    const response = {
      candidates: [
        {
          content: {
            parts: [{ text: content }],
            role: 'model',
          },
          finishReason: chunk.done ? ('STOP' as FinishReason) : undefined,
          index: 0,
        },
      ],
      usageMetadata: {
        promptTokenCount: 0,
        candidatesTokenCount: 0,
        totalTokenCount: 0,
      },
      // Add the getters that the class would have
      get text() {
        return content;
      },
      get functionCalls() {
        return undefined;
      },
      get executableCode() {
        return undefined;
      },
      get codeExecutionResult() {
        return undefined;
      },
      data: undefined,
    } as GenerateContentResponse;

    return response;
  }

  private extractTextContent(contents: any[]): string {
    let text = '';
    
    for (const content of contents) {
      if (typeof content === 'string') {
        text += content;
      } else if (content && typeof content === 'object') {
        if (content.parts) {
          // It's a Content object with parts
          for (const part of content.parts) {
            if (typeof part === 'string') {
              text += part;
            } else if (part && part.text) {
              text += part.text;
            }
            // Note: Ollama doesn't support function calls in the same way as Gemini
            // We'll convert function calls to text descriptions for now
            if (part && part.functionCall) {
              text += `[Function call: ${part.functionCall.name}]`;
            }
            if (part && part.functionResponse) {
              text += `[Function response: ${JSON.stringify(part.functionResponse.response)}]`;
            }
          }
        } else if (content.text) {
          // It's a Part object with text
          text += content.text;
        }
      }
    }
    
    return text;
  }
}

export async function createOllamaContentGenerator(
  config: ContentGeneratorConfig,
): Promise<ContentGenerator> {
  return new OllamaContentGenerator(config);
}