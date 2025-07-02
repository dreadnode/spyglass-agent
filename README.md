# Spyglass Agent - Red Team CLI Tool

[![Spyglass Agent CI](https://github.com/dreadnode/spyglass-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/dreadnode/spyglass-agent/actions/workflows/ci.yml)

![Spyglass Agent Screenshot](./docs/assets/spyglass-screenshot.png)

This repository contains Spyglass Agent, a command-line AI workflow tool designed specifically for red teaming and offensive security operations. Built on a foundation adapted from Google's Gemini CLI, it provides intelligent assistance for security testing workflows.

With Spyglass Agent you can:

- Analyze large codebases for vulnerability discovery and security assessments.
- Generate security reports and documentation from assessment findings.
- Automate red teaming tasks, like reconnaissance, vulnerability scanning, and exploit research.
- Use tools and MCP servers to connect specialized security capabilities and frameworks.
- Conduct context-aware security analysis with multi-modal capabilities.
- Integrate with existing security tools and workflows.

**Important**: This tool should only be used for authorized security testing and educational purposes. Ensure you have proper authorization before conducting any security assessments.

## Quickstart

1. **Prerequisites:** Ensure you have [Node.js version 18](https://nodejs.org/en/download) or higher installed.
2. **Run the CLI:** Execute the following command in your terminal:

   ```bash
   npx https://github.com/dreadnode/spyglass-agent
   ```

   Or install it with:

   ```bash
   npm install -g @dreadnode/spyglass-agent
   spyglass
   ```

3. **Pick a color theme**
4. **Choose your AI backend:** Spyglass Agent supports multiple AI backends for maximum flexibility and security.

You are now ready to use Spyglass Agent for your authorized security testing!

## AI Backend Configuration

Spyglass Agent supports multiple AI backends to meet different security and operational requirements. You can switch backends using environment variables or by saving preferences in your settings file.

### Quick Backend Selection

**Environment Variables (Recommended)**
```bash
# Use environment variables for temporary backend selection
export SPYGLASS_MODEL_BACKEND=anthropic  # or openai, gemini, ollama
export SPYGLASS_MODEL=claude-3-5-sonnet-20241022  # Optional: specific model
spyglass
```

**Settings File (Persistent)**
```bash
# Save backend preference permanently 
spyglass --auth anthropic  # Interactive setup wizard
```

### Supported Backends

#### 🤖 Anthropic Claude (Recommended)
High-quality reasoning and code analysis capabilities:

```bash
# 1. Get API key from https://console.anthropic.com/account/keys
export ANTHROPIC_API_KEY="sk-ant-..."

# 2. Use with Spyglass
export SPYGLASS_MODEL_BACKEND=anthropic
export SPYGLASS_MODEL=claude-3-5-sonnet-20241022  # Optional
spyglass
```

**Available Models:**
- `claude-3-5-sonnet-20241022` - Best balance (recommended)
- `claude-3-5-haiku-20241022` - Fastest
- `claude-3-opus-20240229` - Most capable

#### 🧠 OpenAI GPT (Popular)
Industry-leading models with broad capabilities:

```bash
# 1. Get API key from https://platform.openai.com/api-keys
export OPENAI_API_KEY="sk-..."

# 2. Use with Spyglass
export SPYGLASS_MODEL_BACKEND=openai
export SPYGLASS_MODEL=gpt-4o  # Optional
spyglass
```

**Available Models:**
- `gpt-4o` - Latest multimodal (recommended)
- `gpt-4-turbo` - Fast and capable
- `gpt-4` - Most capable

#### 🔒 Ollama (Local/Air-Gapped)
Local model execution for maximum privacy and OPSEC:

```bash
# 1. Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# 2. Start service
ollama serve

# 3. Pull security-focused models
ollama pull llama3.1        # General purpose (4.7GB)
ollama pull codellama       # Code analysis (3.8GB)

# 4. Use with Spyglass
export SPYGLASS_MODEL_BACKEND=ollama
export SPYGLASS_MODEL=llama3.1  # Optional
spyglass
```

**Benefits:**
- Air-gapped operation - No internet required
- Complete data privacy - Nothing leaves your machine
- No API costs - Unlimited usage
- OPSEC friendly - No cloud provider logs

#### 🔍 Google Gemini (Advanced)
Google's latest models with strong reasoning:

```bash
# 1. Get API key from https://aistudio.google.com/app/apikey
export GEMINI_API_KEY="..."

# 2. Use with Spyglass
export SPYGLASS_MODEL_BACKEND=gemini
spyglass
```

#### 🏢 Google Vertex AI (Enterprise)
Enterprise Google Cloud integration:

```bash
export GOOGLE_API_KEY="..."
export GOOGLE_CLOUD_PROJECT="your-project"
export GOOGLE_CLOUD_LOCATION="us-central1"
export SPYGLASS_MODEL_BACKEND=vertex
```

### Configuration Precedence

Spyglass Agent uses this priority order for backend selection:

1. **Environment Variables** (highest priority)
   ```bash
   export SPYGLASS_MODEL_BACKEND=anthropic  # Overrides everything
   ```

2. **Settings File** (persistent preferences)
   ```bash
   ~/.spyglass/settings.json  # Saved preferences
   ```

3. **Auto-Detection** (fallback)
   - Detects available API keys automatically
   - Priority: OpenAI → Anthropic → Gemini → Vertex AI → Ollama

### Switching Backends

**Temporary (session-only):**
```bash
SPYGLASS_MODEL_BACKEND=anthropic spyglass  # Just this run
```

**Permanent (save preference):**
```bash
echo '{"selectedAuthType": "anthropic"}' > ~/.spyglass/settings.json
```

**In-CLI commands:**
```bash
/auth anthropic     # Switch and save preference
/auth status        # Show current backend
```

3. Configure your usage tier based on your security testing requirements.

For other authentication methods and security configurations, see the [authentication](./docs/cli/authentication.md) guide.

## Examples

Once the CLI is running, you can start conducting security analysis from your shell.

You can start a security assessment from a target directory:

```sh
cd target-application/
spyglass
> Analyze this codebase for common security vulnerabilities and provide a prioritized list
```

Or work with an existing security project:

```sh
git clone https://github.com/target-org/webapp
cd webapp
spyglass
> Generate a comprehensive security assessment report for this web application
```

### Next steps

- Learn how to [contribute to or build from the source](./CONTRIBUTING.md).
- Explore the available **[CLI Commands](./docs/cli/commands.md)**.
- If you encounter any issues, review the **[Troubleshooting guide](./docs/troubleshooting.md)**.
- For more comprehensive documentation, see the [full documentation](./docs/index.md).
- Take a look at some [security-focused tasks](#security-focused-tasks) for more inspiration.

### Troubleshooting

Head over to the [troubleshooting](docs/troubleshooting.md) guide if you're
having issues.

## Security-focused tasks

### Vulnerability discovery and analysis

Start by `cd`ing into a target codebase and running `spyglass`.

```text
> Identify potential SQL injection vulnerabilities in this codebase and suggest remediation strategies.
```

```text
> Analyze the authentication mechanisms for security weaknesses and privilege escalation paths.
```

### Security assessments and reporting

```text
> Create a comprehensive penetration testing report based on my findings in issues #45-67.
```

```text
> Help me develop a security remediation plan for the vulnerabilities identified in this audit.
```

### Red team automation

Use MCP servers to integrate specialized security tools with your assessment workflows.

```text
> Automate reconnaissance of this target domain and generate an attack surface analysis.
```

```text
> Create a dashboard showing vulnerability trends across our recent assessments.
```

### Security tool integration

```text
> Parse these Nmap scan results and identify the most promising attack vectors.
```

```text
> Analyze these log files for indicators of compromise and generate an incident timeline.
```

### Responsible disclosure and documentation

```text
> Generate a properly formatted vulnerability disclosure report for this critical finding.
```

```text
> Create documentation for this security tool integration following responsible disclosure guidelines.
```

## Purpose & Scope

This tool is designed exclusively for **defensive security purposes**, including:
- Security assessment and penetration testing
- Vulnerability research and analysis  
- Red team exercises and training
- Security tool automation and integration
- Defensive posture evaluation

**Always ensure proper authorization before testing and follow responsible disclosure practices.**

### Uninstall

Head over to the [Uninstall](docs/Uninstall.md) guide for uninstallation instructions.

## Terms of Service and Privacy Notice

For details on the terms of service and privacy notice applicable to your use of Spyglass Agent, see the [Terms of Service and Privacy Notice](./docs/tos-privacy.md).

