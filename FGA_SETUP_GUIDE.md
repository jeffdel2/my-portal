# Auth0 FGA Integration Setup Guide

## Overview
This guide will help you set up Auth0 Fine-Grained Authorization (FGA) alongside your existing RBAC system.

## What We've Built

### 1. **FGA Client Configuration** (`fga-client.js`)
- OpenFGA SDK client configured for Auth0 FGA
- Handles authentication and API communication

### 2. **FGA Middleware** (`fga-middleware.js`)
- Core FGA functionality (check relationships, create/delete tuples)
- Express middleware for FGA authorization checks

### 3. **RBAC-FGA Bridge** (`fga-rbac-bridge.js`)
- Bridges your existing RBAC system with FGA
- Handles tier-based permissions and resource-specific access
- Manages resource ownership and sharing

### 4. **Authorization Model** (`auth-model.fga`)
- FGA model that aligns with your existing RBAC tiers
- Defines relationships for documents, projects, transactions, and balance
- Includes tier-based permissions (free, subscriber, premium)

## Environment Variables Needed

Add these to your `.env` file:

```bash
# Auth0 FGA Configuration
FGA_API_URL=https://api.us1.fga.dev  # Replace with your region
FGA_STORE_ID=your_store_id_here
FGA_AUTHORIZATION_MODEL_ID=your_model_id_here
FGA_API_TOKEN_ISSUER=auth.fga.dev
FGA_API_AUDIENCE=https://api.us1.fga.dev/
FGA_CLIENT_ID=your_fga_client_id
FGA_CLIENT_SECRET=your_fga_client_secret
```

## Setup Steps

### 1. Create Auth0 FGA Account
1. Go to https://dashboard.fga.dev
2. Sign in with your Auth0 credentials
3. Create a new store

### 2. Create Authorization Model
1. In the FGA dashboard, go to "Model Explorer"
2. Copy the content from `auth-model.fga` into the model editor
3. Save the model
4. Note the Model ID from the response

### 3. Get API Credentials
1. In the FGA dashboard, go to "Settings" > "API Keys"
2. Create a new API key
3. Note the Client ID and Client Secret

### 4. Update Environment Variables
1. Add the FGA configuration to your `.env` file
2. Replace placeholder values with your actual credentials

### 5. Test the Integration
1. Start your application: `npm start`
2. Test the FGA routes:
   - `GET /fga-test` - Basic FGA functionality test
   - `GET /my-documents` - List user's accessible documents
   - `POST /documents` - Create a new document (requires subscriber+ tier)
   - `GET /documents/:id` - Access a specific document
   - `POST /documents/:id/share` - Share a document with another user

## How It Works

### RBAC + FGA Integration
1. **RBAC Layer**: Your existing tier system (free, subscriber, premium) provides broad access control
2. **FGA Layer**: Fine-grained permissions for specific resources and actions
3. **Bridge**: The `RBACFGABridge` class combines both systems

### Example Flow
1. User tries to access a document
2. System checks RBAC tier (e.g., subscriber required for document creation)
3. System checks FGA permissions (e.g., user owns or has been granted access to specific document)
4. Access granted only if both checks pass

### Resource Types
- **Documents**: Can be owned, viewed, edited, shared
- **Projects**: Support team collaboration
- **Transactions**: Financial operations
- **Balance**: Account balance viewing

### Permission Levels
- **Free Tier**: Can view shared documents, basic access
- **Subscriber Tier**: Can create documents, edit content
- **Premium Tier**: Can delete documents, full access

## API Endpoints

### FGA Test Routes
- `GET /fga-test` - Test FGA connectivity and basic functionality
- `GET /documents/:id` - Access document with FGA permission check
- `GET /premium-documents/:id` - Access premium document (requires subscriber+ tier + FGA permission)

### RBAC + FGA Integration Routes
- `GET /my-documents` - List all documents user can access
- `POST /documents` - Create new document (subscriber+ tier required)
- `POST /documents/:id/share` - Share document with another user
- `GET /documents/:id` - Access specific document (combined RBAC + FGA check)

## Next Steps

1. **Set up your Auth0 FGA account** and get the credentials
2. **Update your `.env` file** with the FGA configuration
3. **Test the integration** using the provided routes
4. **Customize the authorization model** based on your specific needs
5. **Add FGA checks to your existing routes** as needed

## Troubleshooting

### Common Issues
1. **FGA connection errors**: Check your API URL and credentials
2. **Permission denied**: Verify the authorization model is correctly set up
3. **Store not found**: Ensure the Store ID is correct

### Debug Routes
- `GET /debug-rbac` - Check current RBAC status
- `GET /fga-test` - Test FGA connectivity

## Support
- Auth0 FGA Documentation: https://docs.fga.dev
- OpenFGA Documentation: https://openfga.dev

## Updated FGA Test Route

The `/fga-test` route has been enhanced to validate against the `tier_permission` type from the authorization model. It now:

### Tier Validation
- Checks if user has `can_access_free`, `can_access_subscriber`, and `can_access_premium` permissions
- Validates consistency between RBAC tier and FGA tier permissions
- Provides detailed analysis of tier access levels

### Document Permissions
- Tests document-specific permissions (view, edit, delete)
- Lists all documents the user can access
- Demonstrates fine-grained resource access control

### New Routes Added

#### `/setup-fga-tier` (POST)
Sets up the user's tier permissions in FGA based on their current RBAC tier.

**Example Response:**
```json
{
  "message": "FGA tier permissions set up successfully",
  "userId": "auth0|123456789",
  "userTier": "subscriber",
  "fgaSetup": {
    "tierPermission": "tier_permission:global",
    "relationships": [
      "user:auth0|123456789 subscriber_tier tier_permission:global"
    ]
  }
}
```

#### `/sync-rbac-fga` (GET)
Checks and syncs RBAC permissions with FGA tier permissions.

**Example Response:**
```json
{
  "message": "RBAC-FGA sync check completed",
  "userId": "auth0|123456789",
  "rbacInfo": {
    "userTier": "subscriber",
    "userPermissions": ["read:sub"]
  },
  "fgaInfo": {
    "currentTierChecks": {
      "canAccessFree": true,
      "canAccessSubscriber": true,
      "canAccessPremium": false
    },
    "needsSync": false,
    "synced": false
  }
}
```

## Testing the Integration

1. **Set up tier permissions**: `POST /setup-fga-tier`
2. **Test tier validation**: `GET /fga-test`
3. **Check sync status**: `GET /sync-rbac-fga`
4. **Create documents**: `POST /documents` (requires subscriber+ tier)
5. **Access documents**: `GET /documents/:id`
6. **Share documents**: `POST /documents/:id/share`

## Tier Permission Flow

1. User logs in → RBAC determines tier (free/subscriber/premium)
2. Call `/setup-fga-tier` → FGA gets tier permission relationships
3. FGA can now validate tier-based access for resources
4. Both RBAC and FGA work together for comprehensive authorization

## Automatic FGA Tier Setup

The system now automatically sets up FGA tier permissions in two key scenarios:

### 1. **On User Login**
The RBAC middleware has been enhanced to automatically call `RBACFGABridge.setupUserTierPermissions()` whenever a user logs in. This ensures that:

- FGA always has the current tier information for authenticated users
- No manual setup is required
- Tier permissions are synchronized with RBAC on every request

### 2. **During User Upgrade**
The upgrade process now automatically updates FGA tier permissions when a user upgrades their subscription. This ensures that:

- FGA tier permissions are immediately updated after upgrade
- No delay between RBAC tier change and FGA permission update
- Seamless transition between subscription tiers

## How It Works

### Login Flow
1. User logs in → Auth0 authentication
2. RBAC middleware processes access token → determines user tier
3. **NEW**: `RBACFGABridge.setupUserTierPermissions()` is called automatically
4. FGA gets updated with current tier permissions
5. User can now access FGA-protected resources

### Upgrade Flow
1. User initiates upgrade → role assignment via Auth0 Management API
2. User metadata updated
3. **NEW**: `RBACFGABridge.setupUserTierPermissions()` is called with new tier
4. FGA tier permissions updated immediately
5. User re-authenticates with new permissions
6. Both RBAC and FGA are synchronized

## Benefits

- **Automatic Synchronization**: No manual intervention required
- **Real-time Updates**: FGA permissions update immediately with RBAC changes
- **Error Resilience**: FGA setup failures don't break the login/upgrade process
- **Consistent State**: RBAC and FGA are always in sync
- **Seamless Experience**: Users don't need to manually set up FGA permissions

## Manual Override

If needed, you can still manually set up or sync FGA tier permissions using:

- `POST /setup-fga-tier` - Manually set up tier permissions
- `GET /sync-rbac-fga` - Check and sync RBAC with FGA

## Error Handling

The system is designed to be resilient:
- FGA setup failures are logged but don't break the login process
- Users can still access the application even if FGA is temporarily unavailable
- Manual sync routes are available for troubleshooting
