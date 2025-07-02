#!/usr/bin/env node
/**
 * Test script for NetworkReconTool
 * Usage: node test-network-recon.js [target]
 */

import { NetworkReconTool } from './dist/reconnaissance/NetworkReconTool.js';

// Mock engagement context for testing
const mockScope = {
  id: 'test-engagement',
  name: 'NetworkRecon Test',
  timeline: {
    start: new Date(),
    end: new Date(Date.now() + 24 * 60 * 60 * 1000)
  },
  domains: ['*'],
  ipRanges: ['0.0.0.0/0'], // Allow all IPs for testing - RESTRICT IN PRODUCTION
  exclusions: [],
  permissions: {
    passiveRecon: true,
    activeScanning: true,
    vulnerabilityTesting: false,
    exploitTesting: false,
    socialEngineering: false,
    physicalAccess: false
  },
  contacts: {
    primary: 'test@example.com',
    emergency: 'emergency@example.com'
  }
};

const mockContext = {
  scope: mockScope,
  user: 'test-user',
  sessionId: `test-${Date.now()}`,
  config: {
    settings: {},
    timeout: {
      connectTimeout: 30000,
      readTimeout: 300000
    }
  },
  logger: (level, message, meta) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}`);
    if (meta) {
      console.log('  Meta:', JSON.stringify(meta, null, 2));
    }
  }
};

async function testNetworkRecon() {
  try {
    console.log('🕵️  Starting NetworkReconTool Test\n');
    
    // Get target from command line args or use default
    const target = process.argv[2] || '127.0.0.1';
    console.log(`Target: ${target}\n`);
    
    // Create tool instance
    const networkRecon = new NetworkReconTool(mockContext);
    
    // Test parameters
    const params = {
      targets: [target],
      scanType: 'quick',
      serviceDetection: true,
      osDetection: false, // Disable OS detection to avoid requiring root
      aggressiveTiming: false,
      preferredTool: 'auto'
    };
    
    console.log('📋 Test Parameters:');
    console.log(JSON.stringify(params, null, 2));
    console.log('\n' + '='.repeat(50) + '\n');
    
    // Execute the tool
    console.log('🚀 Executing NetworkReconTool...\n');
    const result = await networkRecon.execute(params);
    
    // Display results
    console.log('\n' + '='.repeat(50));
    console.log('📊 RESULTS');
    console.log('='.repeat(50));
    
    console.log(`✅ Success: ${result.success}`);
    
    if (!result.success) {
      console.log(`❌ Error: ${result.error}`);
      return;
    }
    
    // Show execution metrics
    if (result.metrics) {
      console.log(`⏱️  Execution Time: ${result.metrics.executionTime}ms`);
      console.log(`📡 Request Count: ${result.metrics.requestCount}`);
      console.log(`💾 Data Size: ${result.metrics.dataSize} bytes`);
    }
    
    // Show discovered services
    if (result.reconData?.openPorts) {
      console.log(`\n🔍 Open Ports Found: ${result.reconData.openPorts.length}`);
      result.reconData.openPorts.forEach(port => {
        console.log(`  • ${port.host}:${port.port}/${port.protocol} - ${port.service}${port.version ? ` (${port.version})` : ''}`);
      });
    }
    
    // Show security findings
    if (result.findings && result.findings.length > 0) {
      console.log(`\n🚨 Security Findings: ${result.findings.length}`);
      
      const severityCounts = result.findings.reduce((counts, finding) => {
        counts[finding.severity] = (counts[finding.severity] || 0) + 1;
        return counts;
      }, {});
      
      Object.entries(severityCounts).forEach(([severity, count]) => {
        const emoji = severity === 'critical' ? '🚨' : severity === 'high' ? '⚠️' : severity === 'medium' ? '⚡' : '📝';
        console.log(`  ${emoji} ${severity.toUpperCase()}: ${count}`);
      });
      
      console.log('\n📋 Finding Details:');
      result.findings.slice(0, 5).forEach((finding, i) => {
        console.log(`  ${i + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(`     Target: ${finding.target}:${finding.port}`);
        console.log(`     Impact: ${finding.impact}`);
        console.log(`     Remediation: ${finding.remediation}`);
        console.log('');
      });
      
      if (result.findings.length > 5) {
        console.log(`     ... and ${result.findings.length - 5} more findings`);
      }
    }
    
    // Show raw tool data
    if (result.data) {
      console.log(`\n🛠️  Tool Used: ${result.data.tool}`);
      console.log(`📝 Scan Type: ${result.data.scanParams.scanType}`);
    }
    
    console.log('\n✅ Test completed successfully!');
    
  } catch (error) {
    console.error('\n❌ Test failed:');
    console.error(error.message);
    console.error('\nStack trace:');
    console.error(error.stack);
    process.exit(1);
  }
}

// Check if nmap or rustscan is available
async function checkDependencies() {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);
  
  console.log('🔍 Checking tool dependencies...\n');
  
  const tools = ['nmap', 'rustscan'];
  const available = [];
  
  for (const tool of tools) {
    try {
      await execAsync(`which ${tool}`);
      console.log(`✅ ${tool} is available`);
      available.push(tool);
    } catch {
      console.log(`❌ ${tool} is not available`);
    }
  }
  
  if (available.length === 0) {
    console.log('\n⚠️  WARNING: Neither nmap nor rustscan is installed!');
    console.log('Please install at least one of these tools:');
    console.log('  • nmap: brew install nmap (macOS) or apt-get install nmap (Ubuntu)');
    console.log('  • rustscan: cargo install rustscan');
    console.log('\nThe test will fail without these dependencies.\n');
  } else {
    console.log(`\n🎉 Found ${available.length} tool(s): ${available.join(', ')}\n`);
  }
  
  return available.length > 0;
}

// Main execution
console.log('🕵️‍♂️ Spyglass Agent - NetworkReconTool Test');
console.log('=' * 50);

checkDependencies().then(hasTools => {
  if (hasTools || process.argv.includes('--force')) {
    testNetworkRecon();
  } else {
    console.log('Use --force to run the test anyway (it will likely fail).');
    process.exit(1);
  }
});