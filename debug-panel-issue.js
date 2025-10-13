const { FGAMiddleware } = require('./fga-middleware');

/**
 * Debug script to help identify panel enrollment issues
 */
async function debugPanelIssue() {
  try {
    console.log('🔍 Debugging panel enrollment issue...\n');
    
    // Test user ID (replace with actual user ID experiencing the issue)
    const testUserId = 'auth0|test-user-123';
    
    console.log('1. Testing FGA connectivity...');
    try {
      const { fgaClient } = require('./fga-client');
      console.log('   ✅ FGA client loaded successfully');
    } catch (error) {
      console.log('   ❌ FGA client error:', error.message);
      return;
    }
    
    console.log('\n2. Checking panel enrollment setup...');
    try {
      const canClaim = await FGAMiddleware.canClaimPanel(testUserId);
      console.log(`   Can claim panel: ${canClaim}`);
    } catch (error) {
      console.log('   ❌ Error checking can claim:', error.message);
    }
    
    console.log('\n3. Checking active panel status...');
    try {
      const hasActive = await FGAMiddleware.hasActivePanel(testUserId);
      console.log(`   Has active panel: ${hasActive}`);
    } catch (error) {
      console.log('   ❌ Error checking active panel:', error.message);
    }
    
    console.log('\n4. Getting detailed panel info...');
    try {
      const panelInfo = await FGAMiddleware.getUserPanelInfo(testUserId);
      console.log('   Panel info:', JSON.stringify(panelInfo, null, 2));
    } catch (error) {
      console.log('   ❌ Error getting panel info:', error.message);
    }
    
    console.log('\n5. Testing panel claim process...');
    try {
      // First check if user can claim
      const canClaim = await FGAMiddleware.canClaimPanel(testUserId);
      if (canClaim) {
        console.log('   User can claim panel, testing claim process...');
        
        // Try to claim panel
        await FGAMiddleware.claimPanel(testUserId, 'debug-test');
        console.log('   ✅ Panel claimed successfully');
        
        // Check status immediately after claim
        const hasActiveAfter = await FGAMiddleware.hasActivePanel(testUserId);
        console.log(`   Has active panel after claim: ${hasActiveAfter}`);
        
        // Get fresh panel info
        const panelInfoAfter = await FGAMiddleware.getUserPanelInfo(testUserId);
        console.log('   Panel info after claim:', JSON.stringify(panelInfoAfter, null, 2));
        
      } else {
        console.log('   User cannot claim panel (may already have one)');
      }
    } catch (error) {
      console.log('   ❌ Error in panel claim process:', error.message);
    }
    
    console.log('\n✅ Debug completed!');
    
  } catch (error) {
    console.error('❌ Debug failed:', error);
  }
}

// Run the debug if this file is executed directly
if (require.main === module) {
  debugPanelIssue()
    .then(() => {
      console.log('Debug completed.');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Debug failed:', error);
      process.exit(1);
    });
}

module.exports = { debugPanelIssue };
