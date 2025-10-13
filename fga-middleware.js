const { fgaClient } = require('./fga-client');

// FGA Middleware that works alongside existing RBAC
class FGAMiddleware {
  /**
   * Check if user has a specific relationship to a resource
   * @param {string} user - User ID (from Auth0)
   * @param {string} relation - Relationship to check (e.g., 'viewer', 'owner', 'editor')
   * @param {string} object - Object to check (e.g., 'document:123', 'project:456')
   * @returns {Promise<boolean>} - Whether the relationship exists
   */
  static async checkRelationship(user, relation, object) {
    try {
      const { allowed } = await fgaClient.check({
        user: `user:${user}`,
        relation: relation,
        object: object,
      });
      return allowed;
    } catch (error) {
      console.error('FGA check error:', error);
      return false; // Fail closed for security
    }
  }

  /**
   * Create a new relationship tuple
   * @param {string} user - User ID
   * @param {string} relation - Relationship type
   * @param {string} object - Object ID
   */
  static async createRelationship(user, relation, object) {
    try {
      await fgaClient.writeTuples([{
        user: `user:${user}`,
        relation: relation,
        object: object,
      }]);
      console.log(`Created FGA relationship: user:${user} ${relation} ${object}`);
    } catch (error) {
      console.error('FGA write error:', error);
      throw error;
    }
  }

  /**
   * Delete a relationship tuple
   * @param {string} user - User ID
   * @param {string} relation - Relationship type
   * @param {string} object - Object ID
   */
  static async deleteRelationship(user, relation, object) {
    try {
      await fgaClient.writeTuples([], {
        deletes: [{
          user: `user:${user}`,
          relation: relation,
          object: object,
        }]
      });
      console.log(`Deleted FGA relationship: user:${user} ${relation} ${object}`);
    } catch (error) {
      console.error('FGA delete error:', error);
      throw error;
    }
  }
  /**
   * Write multiple relationship tuples to FGA
   * @param {Array} tuples - Array of relationship tuples to write
   * @param {Object} options - Optional configuration (e.g., deletes array)
   */
  static async writeTuples(tuples, options = {}) {
    try {
      const writes = tuples || [];
      const deletes = options.deletes || [];
      
      // Validate that we have at least one write or delete
      if (writes.length === 0 && deletes.length === 0) {
        console.log('No writes or deletes to perform');
        return;
      }
      
      // Prepare the writeTuples call
      const writeTuplesOptions = {};
      if (deletes.length > 0) {
        writeTuplesOptions.deletes = deletes;
      }
      
      // Call writeTuples with writes and/or deletes
      await fgaClient.writeTuples(writes, writeTuplesOptions);
      
      console.log(`FGA writeTuples completed: ${writes.length} writes, ${deletes.length} deletes`);
    } catch (error) {
      console.error('FGA writeTuples error:', error);
      throw error;
    }
  }


  /**
   * List all objects a user has a specific relationship with
   * @param {string} user - User ID
   * @param {string} relation - Relationship type
   * @param {string} type - Object type (e.g., 'document', 'project')
   * @returns {Promise<Array>} - Array of object IDs
   */
  static async listUserObjects(user, relation, type) {
    try {
      const { objects } = await fgaClient.listObjects({
        user: `user:${user}`,
        relation: relation,
        type: type,
      });
      return objects || [];
    } catch (error) {
      console.error('FGA list objects error:', error);
      return [];
    }
  }

  /**
   * Express middleware factory for FGA checks
   * @param {string} relation - Relationship to check
   * @param {Function} objectExtractor - Function to extract object from request
   * @returns {Function} - Express middleware
   */
  static requireFGA(relation, objectExtractor) {
    return async (req, res, next) => {
      try {
        // Skip FGA check if user doesn't have basic RBAC permissions
        if (!req.oidc || !req.oidc.user) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const userId = req.oidc.user.sub;
        const object = objectExtractor(req);
        
        if (!object) {
          return res.status(400).json({ error: 'Invalid resource' });
        }

        const hasPermission = await this.checkRelationship(userId, relation, object);
        
        if (!hasPermission) {
          return res.status(403).json({ 
            error: 'Access denied', 
            message: `You don't have ${relation} permission for this resource` 
          });
        }

        next();
      } catch (error) {
        console.error('FGA middleware error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
      }
    };
  }

  /**
   * Check if user has an active panel enrollment
   * @param {string} userId - User ID (from Auth0)
   * @returns {Promise<boolean>} - Whether the user has an active panel
   */
  static async hasActivePanel(userId) {
    try {
      console.log(`🔍 Checking active panel for user: ${userId}`);
      
      // Method 1: Check specific panel enrollment directly
      const checkResult = await fgaClient.check({
        user: `user:${userId}`,
        relation: 'active',
        object: 'panel_enrollment:default',
      });
      
      console.log(`FGA direct check result for user ${userId}:`, checkResult);
      
      if (checkResult.allowed) {
        console.log(`✅ User ${userId} has active panel (direct check)`);
        return true;
      }
      
      // Method 2: List all objects the user has 'active' relation to
      const listResult = await fgaClient.listObjects({
        user: `user:${userId}`,
        relation: 'active',
        type: 'panel_enrollment',
      });
      
      console.log(`FGA listObjects result for user ${userId}:`, JSON.stringify(listResult, null, 2));
      
      // Check if we have any panel enrollments
      if (listResult && listResult.objects && listResult.objects.length > 0) {
        console.log(`✅ User ${userId} has active panel (listObjects found ${listResult.objects.length} objects)`);
        return true;
      }
      
      // Method 3: Alternative - check if user owns any panels
      const panelOwnership = await fgaClient.listObjects({
        user: `user:${userId}`,
        relation: 'owner',
        type: 'panel',
      });
      
      console.log(`FGA panel ownership for user ${userId}:`, JSON.stringify(panelOwnership, null, 2));
      
      if (panelOwnership && panelOwnership.objects && panelOwnership.objects.length > 0) {
        console.log(`✅ User ${userId} has active panel (owns ${panelOwnership.objects.length} panels)`);
        return true;
      }
      
      console.log(`❌ User ${userId} has no active panel`);
      return false;
      
    } catch (error) {
      console.error('FGA panel check error:', error);
      return false; // Fail closed for security
    }
  }

  /**
   * Check if user can claim a panel
   * @param {string} userId - User ID (from Auth0)
   * @returns {Promise<boolean>} - Whether the user can claim a panel
   */
  static async canClaimPanel(userId) {
    try {
      // Check if user can claim a panel (not already enrolled)
      const { allowed } = await fgaClient.check({
        user: `user:${userId}`,
        relation: 'can_claim',
        object: 'panel_enrollment:default',
      });
      return allowed;
    } catch (error) {
      console.error('FGA panel claim check error:', error);
      return false; // Fail closed for security
    }
  }

  /**
   * Claim a panel for a user
   * @param {string} userId - User ID (from Auth0)
   * @param {string} panelId - Panel ID to claim
   * @returns {Promise<void>}
   */
  static async claimPanel(userId, panelId = 'default') {
    try {
      console.log(`Starting panel claim for user ${userId}, panel ${panelId}`);
      
      // Create panel ownership relationship
      const panelTuple = {
        user: `user:${userId}`,
        relation: 'owner',
        object: `panel:${panelId}`,
      };
      
      console.log('Creating panel ownership tuple:', panelTuple);
      await fgaClient.writeTuples([panelTuple]);

      // Create active enrollment relationship
      const enrollmentTuple = {
        user: `user:${userId}`,
        relation: 'active',
        object: `panel_enrollment:${panelId}`,
      };
      
      console.log('Creating panel enrollment tuple:', enrollmentTuple);
      await fgaClient.writeTuples([enrollmentTuple]);

      // Verify the tuples were created
      console.log('Verifying panel claim...');
      const hasActivePanel = await this.hasActivePanel(userId);
      console.log(`Verification result - hasActivePanel: ${hasActivePanel}`);

      console.log(`User ${userId} successfully claimed panel ${panelId}`);
    } catch (error) {
      console.error('FGA panel claim error:', error);
      throw error;
    }
  }

  /**
   * Get user's panel information
   * @param {string} userId - User ID (from Auth0)
   * @returns {Promise<Object>} - Panel information
   */
  static async getUserPanelInfo(userId) {
    try {
      console.log(`Getting panel info for user ${userId}`);
      
      // List all panels the user has access to
      const panelResult = await fgaClient.listObjects({
        user: `user:${userId}`,
        relation: 'owner',
        type: 'panel',
      });

      // List all panel enrollments
      const enrollmentResult = await fgaClient.listObjects({
        user: `user:${userId}`,
        relation: 'active',
        type: 'panel_enrollment',
      });

      const panels = panelResult?.objects || [];
      const enrollments = enrollmentResult?.objects || [];
      const hasActivePanel = enrollments.length > 0;
      
      console.log(`Panel info for user ${userId}:`, {
        panels,
        enrollments,
        hasActivePanel,
        rawPanelResult: panelResult,
        rawEnrollmentResult: enrollmentResult
      });

      return {
        panels,
        enrollments,
        hasActivePanel
      };
    } catch (error) {
      console.error('FGA get panel info error:', error);
      return {
        panels: [],
        enrollments: [],
        hasActivePanel: false
      };
    }
  }

  /**
   * Force refresh panel status (useful for debugging)
   * @param {string} userId - User ID (from Auth0)
   * @returns {Promise<Object>} - Fresh panel information
   */
  static async refreshPanelStatus(userId) {
    try {
      console.log(`Force refreshing panel status for user ${userId}`);
      
      // Get fresh data from FGA
      const panelInfo = await this.getUserPanelInfo(userId);
      const hasActivePanel = await this.hasActivePanel(userId);
      
      return {
        ...panelInfo,
        hasActivePanel,
        refreshed: true,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('FGA refresh panel status error:', error);
      return {
        panels: [],
        enrollments: [],
        hasActivePanel: false,
        refreshed: false,
        error: error.message
      };
    }
  }
}

module.exports = { FGAMiddleware };
