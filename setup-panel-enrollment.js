const { fgaClient } = require('./fga-client');
const { getAllPanelTypes } = require('./panel-config');

/**
 * Setup script to initialize dynamic panel enrollment data in FGA
 * This creates panel enrollment objects for all configured panel types
 */
async function setupPanelEnrollment() {
  try {
    console.log('Setting up dynamic panel enrollment in FGA...');
    
    // Get all panel types from configuration
    const panelTypes = getAllPanelTypes();
    console.log(`Setting up ${panelTypes.length} panel types:`, panelTypes.map(p => p.id));
    
    // Create tuples for each panel type
    const tuples = [];
    
    for (const panelType of panelTypes) {
      // Allow all users to claim each panel type
      tuples.push({
        user: 'user:*',
        relation: 'can_claim',
        object: `panel_enrollment:${panelType.id}`,
      });
    }
    
    // Write all tuples at once
    await fgaClient.writeTuples(tuples);
    
    console.log('✅ Dynamic panel enrollment setup completed successfully!');
    console.log(`All users can now claim ${panelTypes.length} different panel types.`);
    console.log('Panel types configured:', panelTypes.map(p => p.id));
    
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
