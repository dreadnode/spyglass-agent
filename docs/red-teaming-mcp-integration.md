# Spyglass Agent - MCP Red Teaming Tool Integration Plan

## Overview
This document outlines the integration strategy for Model Context Protocol (MCP) servers specifically designed for red teaming and defensive security operations within Spyglass Agent.

## MCP Architecture for Red Teaming

### Core MCP Server Categories

#### 1. **Network Reconnaissance MCP Servers**

##### `mcp-nmap-server`
```json
{
  "name": "nmap",
  "command": "node",
  "args": ["/opt/spyglass/mcp-servers/nmap/index.js"],
  "trust": false,
  "description": "Network discovery and port scanning",
  "tools": [
    {
      "name": "nmap_scan",
      "description": "Perform network scans with scope validation",
      "inputSchema": {
        "type": "object",
        "properties": {
          "targets": {"type": "array", "items": {"type": "string"}},
          "scanType": {"enum": ["syn", "connect", "udp", "comprehensive"]},
          "ports": {"type": "string", "description": "Port range or specific ports"},
          "timing": {"enum": ["T0", "T1", "T2", "T3", "T4", "T5"]},
          "outputFormat": {"enum": ["normal", "xml", "grepable"]}
        }
      }
    }
  ]
}
```

##### `mcp-subdomain-enum-server`
```json
{
  "name": "subdomain-enum",
  "command": "python3",
  "args": ["/opt/spyglass/mcp-servers/subdomain-enum/server.py"],
  "trust": false,
  "description": "Subdomain enumeration and discovery",
  "tools": [
    {
      "name": "enumerate_subdomains",
      "description": "Discover subdomains using multiple techniques",
      "inputSchema": {
        "type": "object",
        "properties": {
          "domain": {"type": "string"},
          "methods": {"type": "array", "items": {"enum": ["passive", "bruteforce", "certificate", "dns"]}},
          "wordlist": {"type": "string", "description": "Path to wordlist file"},
          "depth": {"type": "integer", "minimum": 1, "maximum": 5}
        }
      }
    }
  ]
}
```

#### 2. **Web Application Security MCP Servers**

##### `mcp-burp-suite-server`
```json
{
  "name": "burp-suite",
  "httpUrl": "http://localhost:1337/api/mcp",
  "headers": {"Authorization": "Bearer ${BURP_API_KEY}"},
  "trust": false,
  "description": "Burp Suite Professional API integration",
  "tools": [
    {
      "name": "burp_spider",
      "description": "Spider web application for content discovery",
      "inputSchema": {
        "type": "object",
        "properties": {
          "url": {"type": "string", "format": "uri"},
          "scope": {"type": "array", "items": {"type": "string"}},
          "maxDepth": {"type": "integer", "minimum": 1, "maximum": 10}
        }
      }
    },
    {
      "name": "burp_active_scan",
      "description": "Perform active vulnerability scanning",
      "inputSchema": {
        "type": "object",
        "properties": {
          "url": {"type": "string", "format": "uri"},
          "scanPolicy": {"enum": ["light", "balanced", "thorough", "custom"]},
          "insertionPoints": {"type": "array", "items": {"enum": ["headers", "params", "body"]}}
        }
      }
    }
  ]
}
```

##### `mcp-web-tech-analyzer-server`
```json
{
  "name": "web-tech-analyzer",
  "command": "go",
  "args": ["run", "/opt/spyglass/mcp-servers/web-tech/main.go"],
  "trust": false,
  "description": "Web technology identification and analysis",
  "tools": [
    {
      "name": "identify_technologies",
      "description": "Identify web technologies, frameworks, and versions",
      "inputSchema": {
        "type": "object",
        "properties": {
          "url": {"type": "string", "format": "uri"},
          "aggressive": {"type": "boolean", "default": false},
          "categories": {"type": "array", "items": {"enum": ["cms", "framework", "server", "database", "analytics"]}}
        }
      }
    }
  ]
}
```

#### 3. **Vulnerability Assessment MCP Servers**

##### `mcp-nuclei-server`
```json
{
  "name": "nuclei",
  "command": "nuclei",
  "args": ["-mcp-mode"],
  "trust": false,
  "description": "Fast vulnerability scanner using community templates",
  "tools": [
    {
      "name": "nuclei_scan",
      "description": "Scan targets using Nuclei templates",
      "inputSchema": {
        "type": "object",
        "properties": {
          "targets": {"type": "array", "items": {"type": "string"}},
          "templates": {"type": "array", "items": {"type": "string"}},
          "severity": {"type": "array", "items": {"enum": ["info", "low", "medium", "high", "critical"]}},
          "tags": {"type": "array", "items": {"type": "string"}},
          "rateLimit": {"type": "integer", "minimum": 1, "maximum": 1000}
        }
      }
    }
  ]
}
```

##### `mcp-sqlmap-server`
```json
{
  "name": "sqlmap",
  "command": "python3",
  "args": ["/opt/spyglass/mcp-servers/sqlmap/server.py"],
  "trust": false,
  "description": "SQL injection detection and exploitation",
  "tools": [
    {
      "name": "sqlmap_test",
      "description": "Test for SQL injection vulnerabilities",
      "inputSchema": {
        "type": "object",
        "properties": {
          "url": {"type": "string", "format": "uri"},
          "data": {"type": "string", "description": "POST data"},
          "cookie": {"type": "string"},
          "level": {"type": "integer", "minimum": 1, "maximum": 5},
          "risk": {"type": "integer", "minimum": 1, "maximum": 3},
          "technique": {"enum": ["B", "E", "U", "S", "T", "Q"], "description": "SQL injection techniques"}
        }
      }
    }
  ]
}
```

#### 4. **OSINT and Intelligence MCP Servers**

##### `mcp-osint-server`
```json
{
  "name": "osint",
  "command": "python3",
  "args": ["/opt/spyglass/mcp-servers/osint/server.py"],
  "trust": false,
  "description": "Open source intelligence gathering",
  "tools": [
    {
      "name": "whois_lookup",
      "description": "Perform WHOIS lookups on domains and IPs",
      "inputSchema": {
        "type": "object",
        "properties": {
          "target": {"type": "string"},
          "detailed": {"type": "boolean", "default": false}
        }
      }
    },
    {
      "name": "certificate_transparency",
      "description": "Search certificate transparency logs",
      "inputSchema": {
        "type": "object",
        "properties": {
          "domain": {"type": "string"},
          "includeSubdomains": {"type": "boolean", "default": true}
        }
      }
    }
  ]
}
```

#### 5. **Reporting and Evidence Management MCP Servers**

##### `mcp-report-generator-server`
```json
{
  "name": "report-generator",
  "command": "node",
  "args": ["/opt/spyglass/mcp-servers/reporting/index.js"],
  "trust": true,
  "description": "Generate professional security assessment reports",
  "tools": [
    {
      "name": "generate_report",
      "description": "Generate formatted security assessment report",
      "inputSchema": {
        "type": "object",
        "properties": {
          "template": {"enum": ["executive", "technical", "compliance", "custom"]},
          "findings": {"type": "array", "items": {"$ref": "#/definitions/finding"}},
          "format": {"enum": ["markdown", "html", "pdf", "docx"]},
          "includeEvidence": {"type": "boolean", "default": true}
        }
      }
    }
  ]
}
```

##### `mcp-screenshot-server`
```json
{
  "name": "screenshot",
  "command": "node",
  "args": ["/opt/spyglass/mcp-servers/screenshot/index.js"],
  "trust": false,
  "description": "Automated screenshot capture for evidence collection",
  "tools": [
    {
      "name": "capture_screenshot",
      "description": "Capture screenshots of web applications",
      "inputSchema": {
        "type": "object",
        "properties": {
          "url": {"type": "string", "format": "uri"},
          "fullPage": {"type": "boolean", "default": true},
          "width": {"type": "integer", "default": 1920},
          "height": {"type": "integer", "default": 1080},
          "delay": {"type": "integer", "minimum": 0, "maximum": 10000}
        }
      }
    }
  ]
}
```

## Integration Strategy

### 1. **Scope Validation Layer**
All MCP servers will integrate with a centralized scope validation service:

```typescript
interface ScopeValidator {
  validateTarget(target: string, engagementScope: EngagementScope): Promise<boolean>;
  logAccess(tool: string, target: string, user: string): Promise<void>;
  getApprovedTargets(): Promise<string[]>;
}
```

### 2. **Security Controls**
- **Trust Levels**: MCP servers categorized by trust level and capabilities
- **Rate Limiting**: Automatic rate limiting for network scanning tools
- **Logging**: Comprehensive audit logging for all tool executions
- **Sandboxing**: Isolated execution environments for high-risk tools

### 3. **Configuration Management**
```yaml
# /Users/robmulla/Repos/dreadnode/spyglass-agent/.spyglass/mcp-config.yaml
mcpServers:
  nmap:
    enabled: true
    trust: false
    rateLimit: 100
    maxConcurrent: 5
    allowedNets:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      - "172.16.0.0/12"
  burp-suite:
    enabled: false  # Requires manual activation
    trust: false
    apiKey: "${BURP_API_KEY}"
    proxyUrl: "http://localhost:8080"
  nuclei:
    enabled: true
    trust: false
    templatesPath: "/opt/nuclei-templates"
    updateTemplates: true
```

### 4. **Custom MCP Server Development Kit**

Create a standardized SDK for developing red teaming MCP servers:

```typescript
// packages/redteam-mcp-sdk/src/base-server.ts
export abstract class RedTeamMCPServer extends Server {
  protected scopeValidator: ScopeValidator;
  protected auditLogger: AuditLogger;
  
  abstract validateScope(target: string): Promise<boolean>;
  abstract executeToolSafely(toolName: string, args: any): Promise<any>;
  
  protected async beforeToolExecution(toolName: string, args: any): Promise<void> {
    await this.auditLogger.logToolExecution(toolName, args);
    
    if (!await this.validateScope(args.target)) {
      throw new Error(`Target ${args.target} is outside approved scope`);
    }
  }
}
```

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [ ] Create MCP configuration system
- [ ] Implement scope validation service
- [ ] Set up audit logging infrastructure
- [ ] Develop base MCP server SDK

### Phase 2: Core Tools (Weeks 3-4)
- [ ] Implement `mcp-nmap-server`
- [ ] Implement `mcp-subdomain-enum-server`  
- [ ] Implement `mcp-nuclei-server`
- [ ] Basic reporting MCP server

### Phase 3: Advanced Tools (Weeks 5-6)
- [ ] Implement `mcp-burp-suite-server`
- [ ] Implement `mcp-osint-server`
- [ ] Advanced reporting and evidence management
- [ ] Screenshot and documentation tools

### Phase 4: Integration & Testing (Weeks 7-8)
- [ ] Full integration testing
- [ ] Security controls validation
- [ ] Performance optimization
- [ ] Documentation and user guides

## Security Considerations

### 1. **Network Security**
- All network tools must validate targets against approved scope
- Automatic rate limiting to prevent DoS
- Network segmentation for scanning operations

### 2. **Data Protection**
- Secure storage of engagement data
- Encryption of sensitive findings
- Automatic evidence cleanup after engagement

### 3. **Access Control**
- Role-based access to different MCP servers
- Multi-factor authentication for high-risk operations
- Session management and timeout controls

### 4. **Compliance**
- Audit trail for all security testing activities
- Evidence chain of custody
- Automated compliance reporting

This MCP integration strategy provides a comprehensive framework for extending Spyglass Agent with specialized red teaming capabilities while maintaining strict security controls and ethical boundaries.