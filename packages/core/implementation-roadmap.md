# Multi-Backend Support Implementation Roadmap

## Quick Reference
- **Current Issue**: nextSpeakerChecker fails on non-Gemini backends with HTTP 404
- **Root Cause**: Hardcoded Gemini dependencies in utility components  
- **Immediate Fix**: 15-minute backend detection patch
- **Long-term Solution**: 1-2 week architecture refactor

---

## Phase 1: Immediate Fix (🔥 URGENT - 15 minutes)

### Goal
Stop nextSpeakerChecker failures on Anthropic/OpenAI/Ollama backends so AI red team tool works immediately.

### Implementation Steps

#### Step 1: Modify nextSpeakerChecker.ts
```bash
# File: /packages/core/src/utils/nextSpeakerChecker.ts
# Add after imports, before checkNextSpeaker function:

import { AuthType } from '../core/contentGenerator.js';

# Modify checkNextSpeaker function beginning:
export async function checkNextSpeaker(
  chat: GeminiChat,
  geminiClient: GeminiClient,
  abortSignal: AbortSignal,
): Promise<NextSpeakerResponse | null> {
  // QUICK FIX: Skip nextSpeakerChecker for non-Gemini backends
  const config = geminiClient.getContentGeneratorConfig();
  const isGeminiBackend = config.authType === AuthType.LOGIN_WITH_GOOGLE || 
                         config.authType === AuthType.USE_GEMINI || 
                         config.authType === AuthType.USE_VERTEX_AI;
  
  if (!isGeminiBackend) {
    console.log(`[DEBUG] Skipping nextSpeakerChecker for backend: ${config.authType}`);
    return null; // Graceful degradation - conversation waits for user input
  }
  
  // Rest of existing function unchanged...
```

#### Step 2: Test the Fix
```bash
# Rebuild
npm run build

# Test with Anthropic backend
export SPYGLASS_MODEL_BACKEND=anthropic
export SPYGLASS_MODEL=claude-3-5-sonnet-20241022
spyglass

# Try AI red team tool:
# "Test this AI application: librarian.platform.dreadnode.io/score"
```

#### Step 3: Verify No Regression
```bash
# Test with Gemini backend (should still work fully)
export SPYGLASS_MODEL_BACKEND=gemini
export SPYGLASS_MODEL=gemini-1.5-flash
spyglass

# Verify nextSpeakerChecker still works on Gemini
```

### Expected Results
- ✅ No more HTTP 404 errors on non-Gemini backends
- ✅ AI red team tool works on Anthropic  
- ✅ Conversation flow works (just no auto-continuation)
- ✅ Full functionality preserved on Gemini backends

---

## Phase 2: Backend-Agnostic NextSpeakerChecker (🎯 1-2 days)

### Goal
Make nextSpeakerChecker work properly with all backends, not just skip them.

### Architecture Changes

#### Step 1: Extend ContentGenerator Interface
```typescript
// File: /packages/core/src/core/contentGenerator.ts
export interface ContentGenerator {
  // Existing methods...
  
  // Add JSON generation capability
  generateJson(
    request: GenerateContentParameters, 
    schema: SchemaUnion
  ): Promise<object>;
}
```

#### Step 2: Implement generateJson for Each Backend
```typescript
// Anthropic implementation
async generateJson(request: GenerateContentParameters, schema: SchemaUnion): Promise<object> {
  // Convert schema to Anthropic format and call API
}

// OpenAI implementation  
async generateJson(request: GenerateContentParameters, schema: SchemaUnion): Promise<object> {
  // Convert schema to OpenAI function calling format
}

// Ollama implementation
async generateJson(request: GenerateContentParameters, schema: SchemaUnion): Promise<object> {
  // Use constrained generation or prompt engineering
}
```

#### Step 3: Update nextSpeakerChecker
```typescript
export async function checkNextSpeaker(
  chat: GeminiChat,
  client: GeminiClient,
  abortSignal: AbortSignal,
): Promise<NextSpeakerResponse | null> {
  const contentGenerator = client.getContentGenerator();
  
  try {
    const parsedResponse = await contentGenerator.generateJson(
      { contents: [...curatedHistory, { role: 'user', parts: [{ text: CHECK_PROMPT }] }] },
      RESPONSE_SCHEMA
    ) as NextSpeakerResponse;
    
    return parsedResponse;
  } catch (error) {
    console.warn('Failed to get next speaker decision:', error);
    return null; // Graceful degradation
  }
}
```

### Testing Strategy
- Test JSON generation across all backends
- Verify schema compatibility
- Test nextSpeakerChecker behavior consistency

---

## Phase 3: Complete Architecture Refactor (🚀 1-2 weeks)

### Goal
Remove all Gemini-specific naming and create truly backend-agnostic architecture.

### Major Changes

#### Step 1: Interface Abstractions
```typescript
// New interfaces in /packages/core/src/core/interfaces.ts
interface AIClient {
  sendMessageStream(message: string, signal: AbortSignal): AsyncGenerator<AIResponse>;
  getChat(): AIChat;
  getContentGenerator(): ContentGenerator;
}

interface AIChat {
  getHistory(curated?: boolean): Content[];
  addMessage(message: Content): void;
  streamResponse(response: AIResponse): void;
}
```

#### Step 2: Class Renames
- `GeminiClient` → `AIClient` (with GeminiClient as alias for backward compatibility)
- `GeminiChat` → `AIChat` (with GeminiChat as alias)
- `useGeminiStream` → `useAIStream` (with useGeminiStream as alias)

#### Step 3: Event Type Generalization
```typescript
// Rename Gemini-specific event types
interface AIStreamEvent { /* ... */ }
interface AIToolCallEvent { /* ... */ }
interface AIErrorEvent { /* ... */ }
```

#### Step 4: Update All Components
- CLI components to use new interfaces
- Tool implementations to use AIClient
- Utility functions to be backend-agnostic

### Migration Strategy
1. **Backward Compatibility**: Keep old names as aliases
2. **Gradual Migration**: Update components one by one
3. **Documentation**: Clear migration guide for users
4. **Deprecation Warnings**: Warn about old interface usage

---

## Testing Matrix

### Backends to Test
- ✅ Gemini (OAuth, API Key, Vertex AI)  
- ✅ Anthropic (Claude)
- ✅ OpenAI (GPT models)
- ✅ Ollama (Local models)

### Features to Test
- ✅ Basic conversation flow
- ✅ Tool calling (AI red team tool)
- ✅ nextSpeakerChecker behavior
- ✅ Streaming responses
- ✅ Error handling
- ✅ Backend switching

### Test Scenarios
1. **Single Backend Usage**: Each backend works independently
2. **Backend Switching**: Can switch backends within session
3. **Tool Integration**: All tools work on all backends
4. **Error Recovery**: Graceful handling of backend failures
5. **Performance**: No significant latency differences

---

## Risk Mitigation

### Phase 1 Risks (LOW)
- **Risk**: Breaking Gemini functionality
- **Mitigation**: Add backend detection, don't modify existing logic
- **Rollback**: Simple revert of 5-line change

### Phase 2 Risks (MEDIUM)  
- **Risk**: JSON schema incompatibility across backends
- **Mitigation**: Extensive testing, fallback mechanisms
- **Rollback**: Disable feature for problematic backends

### Phase 3 Risks (HIGH)
- **Risk**: Breaking changes for users
- **Mitigation**: Maintain backward compatibility aliases
- **Rollback**: Feature flags for new vs old interfaces

---

## Success Criteria

### Phase 1 Complete When:
- ✅ AI red team tool works on Anthropic backend
- ✅ No HTTP 404 errors on any backend  
- ✅ No regression on Gemini backends

### Phase 2 Complete When:
- ✅ nextSpeakerChecker works on all 4 backends
- ✅ Consistent auto-continuation behavior
- ✅ No backend-specific code in nextSpeakerChecker

### Phase 3 Complete When:
- ✅ No Gemini-specific naming in generic components
- ✅ Easy to add new backends (5 steps or less)
- ✅ Clean separation of concerns
- ✅ Comprehensive documentation

---

## Next Action Items

### Immediate (Today)
1. 🔥 **Implement Phase 1 fix** (15 minutes)
2. 🔥 **Test AI red team tool on Anthropic** (5 minutes)
3. ✅ **Verify no regression on Gemini** (5 minutes)

### This Week  
1. 🎯 **Design ContentGenerator.generateJson interface**
2. 🎯 **Implement for each backend**
3. 🎯 **Update nextSpeakerChecker to use it**

### This Month
1. 🚀 **Create interface abstractions**
2. 🚀 **Rename core components**  
3. 🚀 **Update all UI components**
4. 🚀 **Write migration documentation**

The **immediate Phase 1 fix takes 15 minutes** and will solve your AI red team tool issue today. The longer phases provide a robust foundation for future backend additions and maintenance.