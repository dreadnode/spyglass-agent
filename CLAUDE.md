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

## Development Notes
- **System Prompt Updates**: When adding new tools or MCP integrations, update the system prompt in `packages/core/src/core/prompts.ts` to include references to new tool names using `${ToolName.Name}` template variables
- **Tool Registry**: New tools should be registered in the tool registry and imported in prompts.ts for proper system prompt integration