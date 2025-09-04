const { OpenFgaClient, CredentialsMethod } = require('@openfga/sdk');

// FGA Client Configuration
const fgaClient = new OpenFgaClient({
  apiUrl: process.env.FGA_API_URL, // e.g., https://api.us1.fga.dev
  storeId: process.env.FGA_STORE_ID,
  authorizationModelId: process.env.FGA_AUTHORIZATION_MODEL_ID,
  credentials: {
    method: CredentialsMethod.ClientCredentials,
    config: {
      apiTokenIssuer: process.env.FGA_API_TOKEN_ISSUER || 'auth.fga.dev',
      apiAudience: process.env.FGA_API_AUDIENCE, // same as apiUrl with trailing slash
      clientId: process.env.FGA_CLIENT_ID,
      clientSecret: process.env.FGA_CLIENT_SECRET,
    },
  },
});

module.exports = { fgaClient };
