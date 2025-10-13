const { FGAMiddleware } = require('./fga-middleware');

/**
 * Test script to verify panel enrollment functionality
 */
async function testPanelEnrollment() {
  try {
    console.log('🧪 Testing panel enrollment functionality...\n');
    
    // Test user ID (replace with actual user ID for testing)
    const testUserId = 'auth0|test-user-123';
    
    console.log('1. Checking if user has active panel...');
    const hasActivePanel = await FGAMiddleware.hasActivePanel(testUserId);
    console.log(`   Has active panel: ${hasActivePanel}`);
    
    console.log('\n2. Checking if user can claim panel...');
    const canClaimPanel = await FGAMiddleware.canClaimPanel(testUserId);
    console.log(`   Can claim panel: ${canClaimPanel}`);
    
    console.log('\n3. Getting user panel info...');
    const panelInfo = await FGAMiddleware.getUserPanelInfo(testUserId);
    console.log(`   Panel info:`, JSON.stringify(panelInfo, null, 2));
    
    if (canClaimPanel && !hasActivePanel) {
      console.log('\n4. Testing panel claim...');
      await FGAMiddleware.claimPanel(testUserId, 'test-panel');
      console.log('   ✅ Panel claimed successfully!');
      
      console.log('\n5. Verifying panel claim...');
      const hasActivePanelAfter = await FGAMiddleware.hasActivePanel(testUserId);
      console.log(`   Has active panel after claim: ${hasActivePanelAfter}`);
      
      const panelInfoAfter = await FGAMiddleware.getUserPanelInfo(testUserId);
      console.log(`   Panel info after claim:`, JSON.stringify(panelInfoAfter, null, 2));
    }
    
    console.log('\n✅ Panel enrollment test completed successfully!');
    
  } catch (error) {
    console.error('❌ Panel enrollment test failed:', error);
    throw error;
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testPanelEnrollment()
    .then(() => {
      console.log('Test completed.');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Test failed:', error);
      process.exit(1);
    });
}

module.exports = { testPanelEnrollment };
