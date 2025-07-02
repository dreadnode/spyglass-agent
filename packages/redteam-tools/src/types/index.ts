/**
 * Type definitions for red team tools and engagement management
 */

export interface EngagementScope {
  /** Unique identifier for the engagement */
  id: string;
  /** Human-readable name for the engagement */
  name: string;
  /** Start and end dates for the engagement */
  timeline: {
    start: Date;
    end: Date;
  };
  /** Approved target domains and subdomains */
  domains: string[];
  /** Approved IP address ranges in CIDR notation */
  ipRanges: string[];
  /** Specific IPs or ranges to exclude from testing */
  exclusions: string[];
  /** Permission levels for different types of testing */
  permissions: {
    passiveRecon: boolean;
    activeScanning: boolean;
    vulnerabilityTesting: boolean;
    exploitTesting: boolean;
    socialEngineering: boolean;
    physicalAccess: boolean;
  };
  /** Contact information for escalation */
  contacts: {
    primary: string;
    emergency: string;
  };
}

export interface SecurityFinding {
  /** Unique identifier for the finding */
  id: string;
  /** Severity level based on CVSS or internal scale */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** CVSS score if applicable */
  cvssScore?: number;
  /** Type/category of vulnerability */
  type: string;
  /** Affected target system */
  target: string;
  /** Port number if applicable */
  port?: number;
  /** Protocol (TCP/UDP) if applicable */
  protocol?: string;
  /** Brief title of the finding */
  title: string;
  /** Detailed description */
  description: string;
  /** Impact assessment */
  impact: string;
  /** Recommended remediation steps */
  remediation: string;
  /** Supporting evidence (screenshots, logs, etc.) */
  evidence: string[];
  /** References to CVEs, advisories, etc. */
  references: string[];
  /** Discovery timestamp */
  discoveredAt: Date;
  /** Tool or method used for discovery */
  discoveredBy: string;
  /** Current status of the finding */
  status: 'new' | 'confirmed' | 'false-positive' | 'remediated' | 'accepted-risk';
}

export interface ReconData {
  /** Discovered subdomains */
  subdomains: Array<{
    domain: string;
    ip?: string;
    status: 'active' | 'inactive' | 'unknown';
    discoveredBy: string;
    timestamp: Date;
  }>;
  /** Open ports and services */
  openPorts: Array<{
    host: string;
    port: number;
    protocol: 'tcp' | 'udp';
    service: string;
    version?: string;
    banner?: string;
    timestamp: Date;
  }>;
  /** Identified technologies */
  technologies: Array<{
    target: string;
    technology: string;
    version?: string;
    confidence: number;
    source: string;
    timestamp: Date;
  }>;
  /** DNS records */
  dnsRecords: Array<{
    domain: string;
    type: string;
    value: string;
    ttl?: number;
    timestamp: Date;
  }>;
}

export interface RedTeamToolConfig {
  /** Tool-specific settings */
  settings: Record<string, any>;
  /** Rate limiting configuration */
  rateLimit?: {
    requestsPerSecond: number;
    burstLimit: number;
  };
  /** Timeout settings */
  timeout?: {
    connectTimeout: number;
    readTimeout: number;
  };
  /** Proxy configuration */
  proxy?: {
    host: string;
    port: number;
    username?: string;
    password?: string;
  };
  /** User agent string */
  userAgent?: string;
  /** Custom headers */
  headers?: Record<string, string>;
}

export interface ToolExecutionContext {
  /** Current engagement scope */
  scope: EngagementScope;
  /** User executing the tool */
  user: string;
  /** Session identifier */
  sessionId: string;
  /** Tool configuration */
  config: RedTeamToolConfig;
  /** Logging function */
  logger: (level: 'debug' | 'info' | 'warn' | 'error', message: string, meta?: any) => void;
}

export interface ToolExecutionResult {
  /** Whether the execution was successful */
  success: boolean;
  /** Result data */
  data?: any;
  /** Error message if execution failed */
  error?: string;
  /** Execution metrics */
  metrics?: {
    executionTime: number;
    requestCount: number;
    dataSize: number;
  };
  /** Generated findings */
  findings?: SecurityFinding[];
  /** Reconnaissance data */
  reconData?: Partial<ReconData>;
}