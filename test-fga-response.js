const { fgaClient } = require('./fga-client');

/**
 * Test script to check FGA response structure
 */
async function testFGAResponse() {
  try {
    console.log('🧪 Testing FGA response structure...\n');
    
    // Test user ID (replace with your actual user ID)
    const testUserId = 'auth0|your-user-id-here';
    
    console.log('1. Testing listObjects response structure...');
    
    // Test panel ownership
    console.log('\n📋 Testing panel ownership:');
    const panelResult = await fgaClient.listObjects({
      user: `user:${testUserId}`,
      relation: 'owner',
      type: 'panel',
    });
    console.log('Panel ownership result:', JSON.stringify(panelResult, null, 2));
    
    // Test panel enrollment
    console.log('\n📋 Testing panel enrollment:');
    const enrollmentResult = await fgaClient.listObjects({
      user: `user:${testUserId}`,
      relation: 'active',
      type: 'panel_enrollment',
    });
    console.log('Panel enrollment result:', JSON.stringify(enrollmentResult, null, 2));
    
    // Test direct check
    console.log('\n📋 Testing direct check:');
    const checkResult = await fgaClient.check({
      user: `user:${testUserId}`,
      relation: 'active',
      object: 'panel_enrollment:default',
    });
    console.log('Direct check result:', JSON.stringify(checkResult, null, 2));
    
    console.log('\n✅ FGA response structure test completed!');
    
  } catch (error) {
    console.error('❌ FGA response test failed:', error);
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testFGAResponse()
    .then(() => {
      console.log('Test completed.');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Test failed:', error);
      process.exit(1);
    });
}

module.exports = { testFGAResponse };
