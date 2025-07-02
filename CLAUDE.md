# Spyglass Agent - Red Team CLI Tool

## Project Overview
Spyglass Agent is a command-line AI workflow tool designed specifically for red teaming and offensive security operations. Built on a foundation adapted from Google's Gemini CLI, it integrates with Claude AI to provide intelligent assistance for security testing workflows.

## Purpose & Scope
This tool is designed exclusively for **defensive security purposes**, including:
- Security assessment and penetration testing
- Vulnerability research and analysis
- Red team exercises and training
- Security tool automation and integration
- Defensive posture evaluation

**Important**: This tool should only be used for authorized security testing and educational purposes. Ensure you have proper authorization before conducting any security assessments.

## Architecture
- **CLI Package** (`@dreadnode/spyglass-agent`): React-based terminal UI
- **Core Package** (`@dreadnode/spyglass-agent-core`): Backend logic and AI integration
- **Tool System**: File operations, shell commands, web search, memory management
- **MCP Integration**: Model Context Protocol for extensible red teaming tools

## Key Features for Red Teaming
- Large codebase analysis for vulnerability discovery
- Automated report generation and documentation
- Integration with security tools via MCP servers
- Context-aware security assessment workflows
- Multi-modal analysis (code, networks, configurations)

## Configuration
- Config directory: `.spyglass/`
- Context file: `CLAUDE.md` (this file)
- Environment variables: `SPYGLASS_*`
- Binary command: `spyglass`

## Red Teaming Tool Integration
The framework supports MCP (Model Context Protocol) servers for specialized red teaming tools:
- Network scanning and enumeration
- Vulnerability scanners
- Exploit frameworks
- Forensics and analysis tools
- Report generation systems

## Usage Guidelines
1. Always ensure proper authorization before testing
2. Document all activities and findings
3. Follow responsible disclosure practices
4. Respect scope limitations and rules of engagement
5. Use for defensive and educational purposes only

## Development Status
This is an early adaptation focused on rebranding and red teaming specialization. The core CLI framework is stable, but red teaming-specific features are under development.

## Local Model Support

### Multi-Backend Architecture
Spyglass Agent now supports multiple AI model backends for enhanced flexibility and security:

- **Ollama (Local)** - For air-gapped environments and data privacy
- **Google Gemini API** - Cloud-based with high performance  
- **Google Vertex AI** - Enterprise Google Cloud integration
- **Google OAuth** - Interactive authentication

### Backend Switching
Users can easily switch between backends using:

**Environment Variable:**
```bash
export SPYGLASS_MODEL_BACKEND=ollama  # or gemini, vertex, oauth
```

**CLI Command:**
```bash
/backend ollama      # Switch to Ollama
/backend gemini      # Switch to Gemini API  
/backend status      # Show current backend
/backend help        # Setup instructions
```

### Ollama Setup (Recommended for Red Teams)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# Pull a model
ollama pull llama3.1       # General purpose
ollama pull codellama      # Code-focused
ollama pull mistral        # Alternative option

# Use with Spyglass
export SPYGLASS_MODEL_BACKEND=ollama
spyglass
```

**Benefits for Red Teams:**
- ✅ **Air-gapped** - No internet required after setup
- ✅ **Data privacy** - All processing happens locally
- ✅ **No API costs** - Free unlimited usage
- ✅ **Custom models** - Can fine-tune for specific domains
- ✅ **OPSEC friendly** - No data sent to cloud providers

## Development Notes
- **System Prompt Updates**: When adding new tools or MCP integrations, update the system prompt in `packages/core/src/core/prompts.ts` to include references to new tool names using `${ToolName.Name}` template variables
- **Tool Registry**: New tools should be registered in the tool registry and imported in prompts.ts for proper system prompt integration

## Red Team Tools Implementation

### NetworkReconTool (IMPLEMENTED)
**Location**: `packages/core/src/tools/network-recon.ts`

**Purpose**: Intelligent network reconnaissance wrapping nmap and rustscan with security-first design.

**Key Features**:
- Smart tool selection (nmap/rustscan with auto-fallback)
- Scope validation against engagement boundaries  
- Automatic security finding generation with CVSS-style severity
- Structured output parsing (XML for nmap, greppable for rustscan)
- OPSEC considerations (rate limiting, stealth timing)
- Comprehensive audit logging with sanitized parameters

**Security Controls**:
- Requires `activeScanning` permission in engagement scope
- Validates all targets against approved IP ranges
- Sanitizes sensitive parameters in logs
- Generates findings for high-risk services (FTP, Telnet, databases)
- Classifies admin services (SSH, RDP, SNMP) appropriately

**Testing**:
- Unit tests: `packages/redteam-tools/src/reconnaissance/NetworkReconTool.test.ts`
- Integration test: `packages/redteam-tools/test-network-recon.js`
- Run test: `cd packages/redteam-tools && npm run build && node test-network-recon.js [target]`

**Dependencies**: Requires `nmap` or `rustscan` installed on system

**Example Usage**:
```javascript
const params = {
  targets: ['192.168.1.0/24'],
  scanType: 'quick',
  serviceDetection: true,
  preferredTool: 'auto'
};
```

**Integration Status**: ✅ INTEGRATED - Available in CLI as `network_recon` tool

### ExternalReconTool (IMPLEMENTED)
**Location**: `packages/core/src/tools/external-recon.ts`

**Purpose**: Comprehensive external reconnaissance for domain intelligence gathering and DNS footprinting.

**Key Features**:
- WHOIS lookup and analysis (domain age, registrar, DNSSEC status)
- DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)
- Subdomain discovery through brute-forcing and dnsrecon integration
- Zone transfer vulnerability testing
- Security finding generation for missing SPF/DMARC/DKIM
- Intelligent subdomain classification (dev/staging, admin panels, backups)

**Security Controls**:
- Requires explicit authorization for target domains
- Validates all operations stay within engagement scope
- Generates findings for DNS misconfigurations
- Identifies exposed non-production environments
- Detects zone transfer vulnerabilities

**Dependencies**: 
- `whois` - Domain registration information
- `dig` - DNS queries (usually pre-installed)
- `dnsrecon` (optional) - Enhanced subdomain discovery

**Example Usage**:
```javascript
const params = {
  domains: ['example.com'],
  reconTypes: ['all'],
  zoneTransfer: true,
  subdomainWordlist: 'medium'
};
```

**Integration Status**: ✅ INTEGRATED - Available in CLI as `external_recon` tool

### Architecture Pattern for Future Tools

The NetworkReconTool establishes the pattern for all red team tools:

1. **Extend RedTeamTool base class** - provides scope validation, audit logging, error handling
2. **Implement required methods**:
   - `getToolName()` - unique identifier
   - `getRequiredPermissions()` - engagement permissions needed
   - `extractTargets()` - for scope validation
   - `executeImpl()` - core tool logic
   - `getParameterSchema()` - JSON schema for parameters
3. **Security-first design** - validate scope, sanitize logs, generate findings
4. **Structured output** - return SecurityFindings and ReconData
5. **Tool wrapping** - intelligently wrap existing security tools
6. **Comprehensive testing** - unit tests and integration tests

### Planned Tools
- **SubdomainEnumTool** - DNS enumeration and subdomain discovery
- **WebTechTool** - Technology stack and CMS detection  
- **VulnScanTool** - Automated vulnerability scanning
- **SecurityReportTool** - Progressive finding documentation and reporting

## UI/UX Branding Updates (Low Priority)

### CLI Icon and Greeting
**Current Status**: Uses generic Gemini branding
- **Icon**: `✦` (in `packages/cli/src/ui/components/messages/AIMessage.tsx:25`)
- **Greeting**: Generic AI responses

**Spyglass Rebranding Ideas**:
- **Icon Options**: `🔍` (magnifying glass), `👁️` (eye), `🕵️` (detective), `⚡` (spyglass-ish), `◉` (scope crosshair)
- **Security-themed Greetings**: 
  - "🔍 Spyglass Agent ready to investigate..."
  - "👁️ Surveillance mode activated. What's the target?"
  - "🕵️ Red team operative standing by..."
  - "⚡ Penetration testing suite loaded and ready..."
  - "◉ Target acquired. What's the mission?"

**Files to Update**:
- Icon: `packages/cli/src/ui/components/messages/AIMessage.tsx`
- Greeting: TBD - need to locate where first response is generated