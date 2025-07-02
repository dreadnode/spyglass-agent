/**
 * Spyglass Agent Red Team Tools SDK
 * 
 * This package provides specialized tools and utilities for red teaming
 * and defensive security operations within the Spyglass Agent framework.
 * 
 * IMPORTANT: This SDK is designed exclusively for authorized security testing
 * and defensive security purposes. All tools must be used within proper
 * engagement scope and with appropriate authorization.
 */

// Base classes and utilities
export * from './base/RedTeamTool.js';
export * from './base/ScopeValidator.js';

// Type definitions
export * from './types/index.js';

// TODO: Add these exports as tools are implemented
// export * from './base/RedTeamMCPServer.js';
export * from './reconnaissance/NetworkReconTool.js';
// export * from './reconnaissance/SubdomainEnumTool.js';
// export * from './reconnaissance/WebTechTool.js';
// export * from './vulnerability-assessment/VulnScanTool.js';
// export * from './vulnerability-assessment/WebVulnTool.js';
// export * from './reporting/ReportGeneratorTool.js';
// export * from './reporting/EvidenceCollectorTool.js';
// export * from './utilities/PayloadGeneratorTool.js';
// export * from './utilities/EncodingTool.js';