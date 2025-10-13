const { fgaClient } = require('./fga-client');

/**
 * Setup script to initialize panel enrollment data in FGA
 * This creates the default panel enrollment object that all users can claim
 */
async function setupPanelEnrollment() {
  try {
    console.log('Setting up panel enrollment in FGA...');
    
    // Create the default panel enrollment object that all users can claim
    // This allows any user to claim a panel enrollment
    await fgaClient.writeTuples([
      {
        user: 'user:*',
        relation: 'can_claim',
        object: 'panel_enrollment:default',
      }
    ]);
    
    console.log('✅ Panel enrollment setup completed successfully!');
    console.log('All users can now claim panel enrollments.');
    
  } catch (error) {
    console.error('❌ Error setting up panel enrollment:', error);
    throw error;
  }
}

// Run the setup if this file is executed directly
if (require.main === module) {
  setupPanelEnrollment()
    .then(() => {
      console.log('Panel enrollment setup completed.');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Panel enrollment setup failed:', error);
      process.exit(1);
    });
}

module.exports = { setupPanelEnrollment };
