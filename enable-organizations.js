/**
 * One-time setup script to enable Organizations support for your Auth0 application
 *
 * Run this with: node enable-organizations.js
 */

require('dotenv').config();
const axios = require('axios');

async function enableOrganizations() {
  try {
    console.log('=== Enabling Organizations for Auth0 Application ===\n');

    // Step 1: Get Management API token
    console.log('1. Getting Management API token...');
    const tokenResponse = await axios.post(`${process.env.MGMT_BASE_URL}/oauth/token`, {
      client_id: process.env.MGMT_CLIENT_ID,
      client_secret: process.env.MGMT_CLIENT_SECRET,
      audience: `${process.env.MGMT_BASE_URL}/api/v2/`,
      grant_type: 'client_credentials',
    });
    const token = tokenResponse.data.access_token;
    console.log('✓ Token obtained\n');

    // Step 2: Update the application to support organizations
    console.log('2. Enabling organizations for application...');
    console.log(`   Client ID: ${process.env.CLIENT_ID}`);

    const updateResponse = await axios.patch(
      `${process.env.MGMT_BASE_URL}/api/v2/clients/${process.env.CLIENT_ID}`,
      {
        organization_usage: 'allow',
        organization_require_behavior: 'no_prompt'
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );

    console.log('✓ Organizations enabled successfully!\n');
    console.log('Configuration:');
    console.log('  - organization_usage:', updateResponse.data.organization_usage);
    console.log('  - organization_require_behavior:', updateResponse.data.organization_require_behavior);
    console.log('\nYou can now use organizations with this application.');

  } catch (error) {
    console.error('✗ Error enabling organizations:', error.message);

    if (error.response) {
      console.error('\nAuth0 API Error:');
      console.error('  Status:', error.response.status);
      console.error('  Message:', error.response.data.message || error.response.data);
    }

    process.exit(1);
  }
}

// Run the script
enableOrganizations();
