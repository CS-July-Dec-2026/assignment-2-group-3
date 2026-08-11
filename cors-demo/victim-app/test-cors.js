/**
 * Automated Test Suite — CORS Security Lab Verification
 * Run with: node test-cors.js
 * (Requires victim-app server to be running on http://localhost:4000)
 */

const http = require('http');

function makeRequest(path, method = 'GET', headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: 'localhost',
      port: 4000,
      path,
      method,
      headers
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function runTests() {
  console.log('🧪 Starting CORS Security Lab Verification Suite...\n');
  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      passed++;
    } else {
      console.log(`  ❌ FAIL: ${message}`);
      failed++;
    }
  }

  try {
    // 1. Ensure server is reachable
    const health = await makeRequest('/api/admin/cors-config');
    assert(health.statusCode === 200, 'BankDash server is up on http://localhost:4000');

    // 2. Set to vulnerable mode
    await makeRequest('/api/admin/toggle-cors', 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ mode: 'vulnerable' }));
    
    // 3. Test Vulnerable CORS mode
    console.log('\n--- Testing VULNERABLE CORS Mode ---');
    const vulnRes = await makeRequest('/api/profile', 'GET', { 'Origin': 'http://localhost:5000' });
    assert(
      vulnRes.headers['access-control-allow-origin'] === 'http://localhost:5000',
      'Vulnerable mode reflects untrusted origin (http://localhost:5000)'
    );
    assert(
      vulnRes.headers['access-control-allow-credentials'] === 'true',
      'Vulnerable mode enables credentials (cookies)'
    );

    // 4. Set to fixed mode
    console.log('\n--- Toggling to FIXED CORS Mode ---');
    await makeRequest('/api/admin/toggle-cors', 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ mode: 'fixed' }));

    // 5. Test Fixed CORS mode with unauthorized origin
    console.log('\n--- Testing FIXED CORS Mode (Attacker Origin) ---');
    const fixedVulnRes = await makeRequest('/api/profile', 'GET', { 'Origin': 'http://localhost:5000' });
    assert(
      fixedVulnRes.headers['access-control-allow-origin'] === undefined,
      'Fixed mode blocks unauthorized origin (http://localhost:5000)'
    );

    // 6. Test Fixed CORS mode with authorized origin
    console.log('\n--- Testing FIXED CORS Mode (Legitimate Origin) ---');
    const fixedLegitRes = await makeRequest('/api/profile', 'GET', { 'Origin': 'http://localhost:4000' });
    assert(
      fixedLegitRes.headers['access-control-allow-origin'] === 'http://localhost:4000',
      'Fixed mode allows legitimate origin (http://localhost:4000)'
    );
    assert(
      fixedLegitRes.headers['access-control-allow-credentials'] === 'true',
      'Fixed mode allows credentials for legitimate origin'
    );
    assert(
      fixedLegitRes.headers['vary'] === 'Origin',
      'Fixed mode includes Vary: Origin header'
    );

    // 7. Reset server back to default vulnerable mode for demo readiness
    await makeRequest('/api/admin/toggle-cors', 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ mode: 'vulnerable' }));

    console.log(`\n========================================`);
    console.log(`Summary: ${passed} Passed, ${failed} Failed`);
    console.log(`========================================\n`);

    process.exit(failed > 0 ? 1 : 0);
  } catch (err) {
    console.error('❌ Error executing CORS tests:', err.message);
    process.exit(1);
  }
}

runTests();
