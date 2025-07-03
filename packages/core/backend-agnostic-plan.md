# Backend-Agnostic Architecture Plan for Spyglass Agent

## Executive Summary

The Spyglass Agent codebase has excellent multi-backend support at the ContentGenerator level, but several core components remain hardcoded to Gemini. This plan outlines a systematic approach to make the system truly backend-agnostic.

## Current Architecture Assessment

### ✅ Well-Designed Components (Already Backend-Agnostic)
1. **ContentGenerator Interface** - Excellent abstraction for AI model backends
2. **Backend Implementations** - Clean separation for each backend (Gemini, Anthropic, OpenAI, Ollama)
3. **Model Backend Selection** - Environment-driven backend switching
4. **AuthType System** - Clear enumeration of different authentication methods

### ❌ Problematic Components (Hardcoded to Gemini)
1. **nextSpeakerChecker** - Uses hardcoded GeminiClient for continuation decisions
2. **GeminiClient class** - Misleading name, actually used for ALL backends
3. **GeminiChat class** - Core chat logic coupled to Gemini-specific patterns
4. **useGeminiStream hook** - UI component hardcoded to Gemini client
5. **Event types** - Gemini-specific naming in generic contexts

## Problem Analysis

### The nextSpeakerChecker Issue
- **Purpose**: Determines if conversation should continue automatically
- **Current Design**: Hardcoded to use `geminiClient.generateJson()`
- **Impact**: Fails on non-Gemini backends with HTTP 404 errors
- **Criticality**: **LOW** - Graceful degradation exists, feature is convenience not requirement

### Root Cause
The system was originally built for Gemini, then backends were bolted on via the ContentGenerator interface, but internal utility functions were never updated to be backend-agnostic.

## Solution Architecture

### Phase 1: Quick Fix (Immediate)
**Goal**: Stop nextSpeakerChecker failures on non-Gemini backends

**Implementation**: Add backend detection to skip nextSpeakerChecker for non-Gemini backends:

```typescript
export async function checkNextSpeaker(
  chat: GeminiChat,
  client: GeminiClient,
  abortSignal: AbortSignal,
): Promise<NextSpeakerResponse | null> {
  // Quick fix: Skip for non-Gemini backends
  const config = client.getContentGeneratorConfig();
  if (config.authType !== AuthType.LOGIN_WITH_GOOGLE && 
      config.authType !== AuthType.USE_GEMINI && 
      config.authType !== AuthType.USE_VERTEX_AI) {
    console.log(`[DEBUG] Skipping nextSpeakerChecker for backend: ${config.authType}`);
    return null; // Graceful degradation - wait for user input
  }
  
  // Existing Gemini implementation...
}
```

**Files to Modify**:
- `/packages/core/src/utils/nextSpeakerChecker.ts`

**Impact**: 
- ✅ Fixes immediate error on Anthropic/OpenAI/Ollama backends
- ✅ Zero breaking changes
- ✅ Maintains full functionality for Gemini backends
- ⚠️ Loses auto-continuation feature on non-Gemini backends (acceptable tradeoff)

### Phase 2: Backend-Agnostic NextSpeakerChecker (Medium-term)
**Goal**: Make nextSpeakerChecker work with all backends

**Design**: Create backend-agnostic version using ContentGenerator interface:

```typescript
export async function checkNextSpeaker(
  chat: AIChat, // Abstracted from GeminiChat
  contentGenerator: ContentGenerator, // Backend-agnostic
  abortSignal: AbortSignal,
): Promise<NextSpeakerResponse | null> {
  // Use ContentGenerator.generateContent() instead of client.generateJson()
  const response = await contentGenerator.generateContent({
    contents: [...curatedHistory, { role: 'user', parts: [{ text: CHECK_PROMPT }] }],
    generationConfig: {
      responseMimeType: 'application/json',
      responseSchema: RESPONSE_SCHEMA
    }
  });
  
  // Parse JSON response consistently across backends
}
```

**Required Changes**:
1. Create `AIChat` interface to abstract GeminiChat
2. Update nextSpeakerChecker to use ContentGenerator
3. Implement JSON schema support across all backends

### Phase 3: Complete Architecture Refactor (Long-term)
**Goal**: Remove all Gemini-specific naming and coupling

**Major Renames**:
- `GeminiClient` → `AIClient` or `UniversalClient`
- `GeminiChat` → `AIChat`
- `useGeminiStream` → `useAIStream`
- Event types: `GeminiEvent` → `AIEvent`

**Interface Abstractions**:
```typescript
interface AIClient {
  sendMessageStream(message: string, signal: AbortSignal): AsyncGenerator<AIResponse>;
  getChat(): AIChat;
  getContentGeneratorConfig(): ContentGeneratorConfig;
}

interface AIChat {
  getHistory(curated?: boolean): Content[];
  addMessage(message: Content): void;
  // ... other chat operations
}
```

## Implementation Priority

### 🔥 Immediate (Phase 1) - 1-2 hours
- Add backend detection to nextSpeakerChecker
- Fix the immediate error blocking AI red team tool usage

### 🎯 Short-term (Phase 2) - 1-2 days  
- Create backend-agnostic nextSpeakerChecker
- Add JSON schema support to all ContentGenerator implementations
- Create AIChat interface abstraction

### 🚀 Long-term (Phase 3) - 1-2 weeks
- Complete naming and interface refactor
- Update all UI components to use backend-agnostic interfaces
- Create migration guide for existing users

## Risk Assessment

### Phase 1 Risks: **LOW**
- ✅ Non-breaking change
- ✅ Graceful degradation already exists
- ✅ Easy to revert if issues arise

### Phase 2 Risks: **MEDIUM**
- ⚠️ Requires testing across all backends
- ⚠️ JSON schema support varies by backend
- ⚠️ Potential for subtle behavior differences

### Phase 3 Risks: **HIGH**
- ❌ Major breaking changes
- ❌ Extensive testing required
- ❌ User migration complexity

## Testing Strategy

### Phase 1 Testing
- Test AI red team tool on all backends (Gemini, Anthropic, OpenAI, Ollama)
- Verify graceful degradation of continuation feature
- Confirm no regression on Gemini backends

### Phase 2 Testing
- Test nextSpeakerChecker across all backends
- Verify JSON schema parsing consistency
- Test conversation continuation behavior

### Phase 3 Testing
- Full regression testing of all features
- Backend switching tests
- UI component testing with new interfaces

## Alternative Approaches Considered

### Option A: Disable nextSpeakerChecker Entirely
- **Pros**: Simplest solution, eliminates complexity
- **Cons**: Loses useful auto-continuation feature for all backends
- **Verdict**: ❌ Too aggressive, loses valuable functionality

### Option B: Per-Backend nextSpeakerChecker Implementations
- **Pros**: Customized for each backend's strengths
- **Cons**: Code duplication, maintenance complexity
- **Verdict**: ❌ Violates DRY principle, hard to maintain

### Option C: ContentGenerator Extension for JSON Generation
- **Pros**: Extends existing abstraction cleanly
- **Cons**: Requires updating all backend implementations
- **Verdict**: ✅ Chosen for Phase 2 (backend-agnostic approach)

## Success Metrics

### Phase 1 Success Criteria
- ✅ No more HTTP 404 errors on non-Gemini backends
- ✅ AI red team tool works on Anthropic backend
- ✅ Zero regression on existing Gemini functionality

### Phase 2 Success Criteria
- ✅ nextSpeakerChecker works on all backends
- ✅ Consistent continuation behavior across backends
- ✅ No backend-specific workarounds needed

### Phase 3 Success Criteria
- ✅ No Gemini-specific naming in generic components
- ✅ Clean separation between backend-specific and generic code
- ✅ Easy to add new backends without touching core components

## Conclusion

The current architecture shows excellent foresight in the ContentGenerator abstraction, but several utility components need updating to be truly backend-agnostic. **Phase 1 provides an immediate fix** for the AI red team tool issue, while **Phases 2 and 3 create a robust, maintainable architecture** for the future.

The recommended approach prioritizes **stability and incremental improvement** over radical changes, ensuring the system remains functional throughout the transition.