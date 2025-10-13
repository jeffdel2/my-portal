# Panel Enrollment System Guide

## Overview
This guide explains the panel enrollment system that allows users to claim and manage their Nielsen Consumer Panel memberships using Auth0 Fine-Grained Authorization (FGA).

## Features

### 1. **Panel Status Checking**
- Users can see their current panel enrollment status on their profile page
- FGA checks if a user has an active panel enrollment
- Visual indicators show whether a user is enrolled or can claim a panel

### 2. **Panel Claiming**
- Users without active panels see a "Claim Panel" button
- One-click panel enrollment process
- Automatic FGA relationship creation
- User metadata updates to track enrollment

### 3. **FGA Integration**
- Panel ownership and enrollment status stored in FGA
- Fine-grained permissions for panel management
- Secure relationship-based access control

## Setup Instructions

### 1. Update FGA Model
The FGA model has been enhanced with panel types:

```fga
# Panel enrollment and management
type panel
  relations
    define owner: [user]
    define member: [user]
    define viewer: [user, user:*]
    define can_view: viewer or member or owner
    define can_edit: member or owner
    define can_delete: owner
    define can_manage: owner
    define can_claim: [user]

# Panel enrollment status
type panel_enrollment
  relations
    define enrolled: [user]
    define pending: [user]
    define active: [user]
    define can_view_status: enrolled or pending or active
    define can_claim: [user:*]
```

### 2. Initialize Panel Enrollment
Run the setup script to initialize panel enrollment data:

```bash
# Via API endpoint
curl -X POST http://localhost:3000/setup-panel-enrollment

# Or via Node.js script
node setup-panel-enrollment.js
```

### 3. Test the Functionality
Run the test script to verify everything works:

```bash
node test-panel-enrollment.js
```

## API Endpoints

### POST `/claim-panel`
Claims a panel enrollment for the authenticated user.

**Request:**
```json
POST /claim-panel
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "message": "Panel claimed successfully",
  "panelId": "default"
}
```

### POST `/setup-panel-enrollment`
Initializes the panel enrollment system in FGA (admin only).

**Request:**
```json
POST /setup-panel-enrollment
```

**Response:**
```json
{
  "success": true,
  "message": "Panel enrollment setup completed successfully"
}
```

## User Experience

### Profile Page Changes
The profile page now shows:

1. **Active Panel Status**: Green alert showing "Active Panel Member"
2. **Claim Panel Option**: Blue alert with "Join the Nielsen Panel" button
3. **Panel Activities**: List of panel-related activities from user metadata

### Panel Claiming Flow
1. User visits profile page
2. If no active panel, sees "Claim Panel" button
3. Clicks button to claim panel
4. System creates FGA relationships
5. Updates user metadata
6. Shows success message
7. Page refreshes to show new status

## FGA Methods

### `FGAMiddleware.hasActivePanel(userId)`
Checks if a user has an active panel enrollment.

### `FGAMiddleware.canClaimPanel(userId)`
Checks if a user can claim a panel (not already enrolled).

### `FGAMiddleware.claimPanel(userId, panelId)`
Claims a panel for a user, creating FGA relationships.

### `FGAMiddleware.getUserPanelInfo(userId)`
Gets comprehensive panel information for a user.

## User Metadata Updates
When a user claims a panel, the system updates their `user_metadata` with:

```json
{
  "devices": [
    {
      "name": "Nielsen Consumer Panel",
      "type": "panel",
      "registered_on": "2024-01-15T10:30:00.000Z",
      "status": "active"
    }
  ],
  "panel_enrolled": true,
  "panel_enrolled_date": "2024-01-15T10:30:00.000Z"
}
```

## Security Considerations

1. **Authentication Required**: All panel operations require user authentication
2. **FGA Permissions**: Panel access controlled by FGA relationships
3. **Fail Closed**: FGA errors default to denying access
4. **User Isolation**: Users can only manage their own panels

## Troubleshooting

### Common Issues

1. **"Panel enrollment status unavailable"**
   - Run the setup script: `POST /setup-panel-enrollment`
   - Check FGA configuration

2. **"You are not eligible to claim a panel"**
   - User may already have an active panel
   - Check FGA relationships

3. **"Failed to claim panel"**
   - Check FGA API connectivity
   - Verify user authentication
   - Check server logs for detailed errors

### Debug Commands

```bash
# Test panel enrollment
node test-panel-enrollment.js

# Check FGA setup
curl -X POST http://localhost:3000/setup-panel-enrollment
```

## Future Enhancements

1. **Multiple Panel Types**: Support for different panel categories
2. **Panel Management**: Allow users to leave panels
3. **Panel Sharing**: Family/household panel sharing
4. **Panel Analytics**: Track panel engagement metrics
5. **Panel Rewards**: Integration with rewards system
