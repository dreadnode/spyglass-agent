# Spyglass Agent

[![CI](https://github.com/dreadnode/spyglass-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/dreadnode/spyglass-agent/actions/workflows/ci.yml)

![Spyglass Agent Screenshot](./docs/assets/spyglass-screenshot.png)

Spyglass Agent is a command-line AI tool for red teaming and security assessments. Built on Google's Gemini CLI foundation, it provides intelligent assistance for authorized security testing workflows.

**Important**: Only use for authorized security testing and educational purposes.

## Quick Start

1. **Prerequisites:** Node.js 18+ required
2. **Install:**
   ```bash
   npm install -g @dreadnode/spyglass-agent
   spyglass
   ```
3. **Setup:** Choose your AI backend and start testing

## Backend Configuration

Spyglass supports multiple AI backends. Configure using environment variables or the interactive setup.

### Anthropic Claude (Recommended)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export SPYGLASS_MODEL_BACKEND=anthropic
spyglass
```

Available models:
- `claude-3-5-sonnet-20241022` (recommended)
- `claude-3-5-haiku-20241022` (fastest)
- `claude-opus-4-20250514` (latest)

### OpenAI GPT
```bash
export OPENAI_API_KEY="sk-..."
export SPYGLASS_MODEL_BACKEND=openai
spyglass
```

Available models:
- `gpt-4o` (recommended)
- `gpt-4-turbo`
- `gpt-4`

### Local Models (Ollama)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull models
ollama pull llama3.1
ollama serve

# Configure Spyglass
export SPYGLASS_MODEL_BACKEND=ollama
spyglass
```

Benefits: Air-gapped operation, complete privacy, no API costs

### Google Gemini
```bash
export GEMINI_API_KEY="..."
export SPYGLASS_MODEL_BACKEND=gemini
spyglass
```

### Google Vertex AI (Enterprise)
```bash
export GOOGLE_CLOUD_PROJECT="your-project"
export SPYGLASS_MODEL_BACKEND=vertexai
spyglass
```

### Configuration Priority
1. **Environment variables** (highest)
2. **Settings file** (`~/.spyglass/settings.json`)
3. **Auto-detection** (fallback)

## Built-in Security Tools

### Network Reconnaissance
```bash
spyglass "scan 192.168.1.0/24 for open ports"
```
- Port scanning with nmap/rustscan
- Service fingerprinting
- Automatic finding generation

### External Reconnaissance
```bash
spyglass "perform OSINT on example.com"
```
- DNS enumeration
- WHOIS analysis
- Subdomain discovery

### Security Reporting
```bash
spyglass "generate security report"
```
- Finding aggregation
- Risk assessment
- Professional reports

## Example Usage

Start from a target directory:
```bash
cd target-application/
spyglass
```

Common tasks:
- "Analyze this codebase for SQL injection vulnerabilities"
- "Create a penetration testing report"
- "Parse these Nmap results and identify attack vectors"
- "Generate vulnerability disclosure documentation"

## Tool Requirements

Some features require external tools:
```bash
# Network scanning
brew install nmap        # macOS
apt-get install nmap     # Ubuntu

# Fast scanning (optional)
cargo install rustscan
```

## Configuration Examples

**Temporary backend switch:**
```bash
SPYGLASS_MODEL_BACKEND=anthropic spyglass
```

**Permanent settings:**
```json
# ~/.spyglass/settings.json
{
  "selectedAuthType": "anthropic",
  "defaultModel": "claude-3-5-sonnet-20241022"
}
```

**In-CLI commands:**
```bash
/auth anthropic     # Switch backend
/theme atom-one-dark # Change theme
```

## Troubleshooting

**Backend issues:**
1. Verify API key: `echo $ANTHROPIC_API_KEY`
2. Test connection: `spyglass "what model are you?"`
3. Check logs: `DEBUG=1 spyglass`

**Migration from Gemini CLI:**
Settings automatically migrate from `~/.gemini/` to `~/.spyglass/`

## Development

```bash
git clone https://github.com/dreadnode/spyglass-agent.git
cd spyglass-agent
npm install
npm test    # 100% test coverage
npm start
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) file.

## Security Notice

- Only test systems you own or have authorization to test
- Follow responsible disclosure practices
- Use appropriate operational security measures
- Review [Security Policy](SECURITY.md) for vulnerability reporting

---

**Remember**: Use responsibly and within legal boundaries.