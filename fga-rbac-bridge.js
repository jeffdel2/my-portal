const { FGAMiddleware } = require('./fga-middleware');

// Bridge between your existing RBAC and FGA
class RBACFGABridge {
  // Simple in-memory cache to avoid repeated FGA calls
  static tierCache = new Map();
  static cacheTimeout = 5 * 60 * 1000; // 5 minutes
  
  /**
   * Get cached tier or check FGA
   * @param {string} userId - User ID
   * @param {string} tier - Tier to check
   * @returns {Promise<boolean>} - Whether tier exists
   */
  static async getCachedTierCheck(userId, tier) {
    const cacheKey = `${userId}:${tier}`;
    const cached = this.tierCache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.exists;
    }
    
    // Check FGA and cache result
    const exists = await FGAMiddleware.checkRelationship(
      userId, 
      `${tier}_tier`, 
      'tier_permission:global'
    );
    
    this.tierCache.set(cacheKey, {
      exists: exists,
      timestamp: Date.now()
    });
    
    return exists;
  }
  
  /**
   * Clear cache for a user (call after tier updates)
   * @param {string} userId - User ID
   */
  static clearUserCache(userId) {
    for (const key of this.tierCache.keys()) {
      if (key.startsWith(`${userId}:`)) {
        this.tierCache.delete(key);
      }
    }
  }
  

  
  /**
   * Create FGA relationships based on user's RBAC tier
   * @param {string} userId - User ID from Auth0
   * @param {string} userTier - User's tier (free, subscriber, premium)
   */
  static async setupUserTierPermissions(userId, userTier) {
    try {
      // Check if tier permissions already exist to avoid duplicates
      const tierRelation = `${userTier}_tier`;
      const alreadyExists = await FGAMiddleware.checkRelationship(
        userId, 
        tierRelation, 
        'tier_permission:global'
      );
      
      if (alreadyExists) {
        console.log(`FGA tier permissions already exist for user ${userId} with tier ${userTier}`);
        return;
      }
      
      const relationships = [];
      
      // Create tier-based permissions
      if (userTier === 'free') {
        relationships.push({
          user: `user:${userId}`,
          relation: 'free_tier',
          object: 'tier_permission:global'
        });
      } else if (userTier === 'subscriber') {
        relationships.push({
          user: `user:${userId}`,
          relation: 'subscriber_tier',
          object: 'tier_permission:global'
        });
      } else if (userTier === 'premium') {
        relationships.push({
          user: `user:${userId}`,
          relation: 'premium_tier',
          object: 'tier_permission:global'
        });
      }
      
      // Write all relationships to FGA
      if (relationships.length > 0) {
        await FGAMiddleware.writeTuples(relationships);
        console.log(`Set up FGA tier permissions for user ${userId} with tier ${userTier}`);
      }
      
    } catch (error) {
      console.error('Error setting up user tier permissions:', error);
      throw error;
    }
  }
  /**
   * Update user's tier permissions in FGA (handles tier changes)
   * @param {string} userId - User ID from Auth0
   * @param {string} newTier - New tier (free, subscriber, premium)
   */
  static async updateUserTierPermissions(userId, newTier) {
    try {
      // Define all possible tier relations
      const allTiers = ['free_tier', 'subscriber_tier', 'premium_tier'];
      const newTierRelation = `${newTier}_tier`;
      
      // Check current tier permissions (with caching)
      const currentTierChecks = {};
      for (const tier of allTiers) {
        currentTierChecks[tier] = await this.getCachedTierCheck(userId, tier.replace('_tier', ''));
      }
      
      // Find which tier the user currently has
      const currentTier = allTiers.find(tier => currentTierChecks[tier]);
      
      // If user already has the correct tier, no need to update
      if (currentTier === newTierRelation) {
        console.log(`User ${userId} already has correct tier ${newTier}`);
        return;
      }
      
      // Double-check: verify the new tier permission doesn't already exist
      const newTierExists = await FGAMiddleware.checkRelationship(
        userId, 
        newTierRelation, 
        'tier_permission:global'
      );
      
      if (newTierExists) {
        console.log(`User ${userId} already has ${newTier} tier permission, skipping update`);
        return;
      }
      
      // Remove old tier permissions if they exist
      const tuplesToDelete = [];
      for (const tier of allTiers) {
        if (currentTierChecks[tier]) {
          tuplesToDelete.push({
            user: `user:${userId}`,
            relation: tier,
            object: 'tier_permission:global'
          });
        }
      }
      
      // Add new tier permission
      const tuplesToAdd = [{
        user: `user:${userId}`,
        relation: newTierRelation,
        object: 'tier_permission:global'
      }];
      
      // Perform the updates in a single call
      if (tuplesToDelete.length > 0 || tuplesToAdd.length > 0) {
        await FGAMiddleware.writeTuples(tuplesToAdd, { deletes: tuplesToDelete });
        console.log(`Updated FGA tier permissions for user ${userId} to ${newTier} (removed ${tuplesToDelete.length}, added ${tuplesToAdd.length})`);
        // Clear cache for this user since we just updated their permissions
        this.clearUserCache(userId);
      }
      
    } catch (error) {
      // Handle specific FGA errors gracefully
      if (error.message && error.message.includes('tuple which already exists')) {
        console.log(`User ${userId} tier permissions already exist, skipping update`);
        return;
      }
      console.error('Error updating user tier permissions:', error);
      throw error;
    }
  }

  
  /**
   * Check if user has access to a resource based on both RBAC and FGA
   * @param {string} userId - User ID
   * @param {string} userTier - User's RBAC tier
   * @param {string} resourceType - Type of resource (document, project, etc.)
   * @param {string} resourceId - ID of the specific resource
   * @param {string} action - Action to perform (view, edit, delete)
   * @returns {Promise<boolean>} - Whether user has access
   */
  static async checkResourceAccess(userId, userTier, resourceType, resourceId, action) {
    try {
      // First check RBAC tier requirements
      const tierAccess = this.checkTierAccess(userTier, resourceType, action);
      if (!tierAccess) {
        return false;
      }
      
      // Then check FGA resource-specific permissions
      const fgaRelation = this.getFGARelation(action);
      const hasFGAPermission = await FGAMiddleware.checkRelationship(
        userId,
        fgaRelation,
        `${resourceType}:${resourceId}`
      );
      
      return hasFGAPermission;
      
    } catch (error) {
      console.error('Error checking resource access:', error);
      return false; // Fail closed for security
    }
  }
  
  /**
   * Check if user's tier allows access to a resource type and action
   * @param {string} userTier - User's tier
   * @param {string} resourceType - Type of resource
   * @param {string} action - Action to perform
   * @returns {boolean} - Whether tier allows access
   */
  static checkTierAccess(userTier, resourceType, action) {
    // Define tier requirements for different resources and actions
    const tierRequirements = {
      'balance': {
        'view': 'subscriber', // Balance requires subscriber tier
        'edit': 'subscriber'
      },
      'document': {
        'view': 'free', // Documents can be viewed by free tier
        'edit': 'subscriber',
        'delete': 'premium'
      },
      'project': {
        'view': 'free',
        'edit': 'subscriber',
        'delete': 'premium'
      },
      'transaction': {
        'view': 'free',
        'edit': 'subscriber',
        'delete': 'premium'
      }
    };
    
    const requiredTier = tierRequirements[resourceType]?.[action] || 'free';
    const tierLevels = { 'free': 0, 'subscriber': 1, 'premium': 2 };
    
    const userLevel = tierLevels[userTier] || 0;
    const requiredLevel = tierLevels[requiredTier] || 0;
    
    return userLevel >= requiredLevel;
  }
  
  /**
   * Map actions to FGA relations
   * @param {string} action - Action (view, edit, delete, share)
   * @returns {string} - FGA relation name
   */
  static getFGARelation(action) {
    const actionMap = {
      'view': 'can_view',
      'edit': 'can_edit',
      'delete': 'can_delete',
      'share': 'can_share'
    };
    
    return actionMap[action] || 'can_view';
  }
  
  /**
   * Create resource ownership in FGA
   * @param {string} userId - User ID
   * @param {string} resourceType - Type of resource
   * @param {string} resourceId - Resource ID
   */
  static async createResourceOwnership(userId, resourceType, resourceId) {
    try {
      await FGAMiddleware.createRelationship(
        userId,
        'owner',
        `${resourceType}:${resourceId}`
      );
      console.log(`Created ownership: user:${userId} owns ${resourceType}:${resourceId}`);
    } catch (error) {
      console.error('Error creating resource ownership:', error);
      throw error;
    }
  }
  
  /**
   * Share a resource with another user
   * @param {string} ownerId - Owner's user ID
   * @param {string} shareWithUserId - User to share with
   * @param {string} resourceType - Type of resource
   * @param {string} resourceId - Resource ID
   * @param {string} permission - Permission level (viewer, editor)
   */
  static async shareResource(ownerId, shareWithUserId, resourceType, resourceId, permission = 'viewer') {
    try {
      // Verify the owner has permission to share
      const canShare = await FGAMiddleware.checkRelationship(
        ownerId,
        'can_share',
        `${resourceType}:${resourceId}`
      );
      
      if (!canShare) {
        throw new Error('User does not have permission to share this resource');
      }
      
      // Create the sharing relationship
      await FGAMiddleware.createRelationship(
        shareWithUserId,
        permission,
        `${resourceType}:${resourceId}`
      );
      
      console.log(`Shared ${resourceType}:${resourceId} with user:${shareWithUserId} as ${permission}`);
    } catch (error) {
      console.error('Error sharing resource:', error);
      throw error;
    }
  }
}

module.exports = { RBACFGABridge };
