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
        return;
      }
      
      // Prepare the writeTuples call
      const writeTuplesOptions = {};
      if (deletes.length > 0) {
        writeTuplesOptions.deletes = {
          tuple_keys: deletes
        };
      }
      
      // Call writeTuples with writes and/or deletes
      await fgaClient.writeTuples(writes, writeTuplesOptions);
      
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
   * Check if user has any active panel enrollments
   * @param {string} userId - User ID (from Auth0)
   * @returns {Promise<boolean>} - Whether the user has any active panels
   */
  static async hasActivePanel(userId) {
    try {
      
      // List all panel enrollments the user has 'active' relation to
      const listResult = await fgaClient.listObjects({
        user: `user:${userId}`,
        relation: 'active',
        type: 'panel_enrollment',
      });
      
      
      // Check if we have any panel enrollments
      if (listResult && listResult.objects && listResult.objects.length > 0) {
        return true;
      }
      return false;
      
    } catch (error) {
      console.error('FGA panel check error:', error);
      return false; // Fail closed for security
    }
  }

  /**
   * Get all active panels for a user
   * @param {string} userId - User ID (from Auth0)
   * @returns {Promise<Array>} - Array of active panel IDs
   */
  static async getActivePanels(userId) {
    try {
      
      const listResult = await fgaClient.listObjects({
        user: `user:${userId}`,
        relation: 'active',
        type: 'panel_enrollment',
      });
      
      const activePanels = listResult?.objects || [];
      
      return activePanels;
      
    } catch (error) {
      console.error('FGA get active panels error:', error);
      return [];
    }
  }

  /**
   * Check if user can claim a specific panel
   * @param {string} userId - User ID (from Auth0)
   * @param {string} panelId - Panel ID to check
   * @returns {Promise<boolean>} - Whether the user can claim the panel
   */
  static async canClaimPanel(userId, panelId = 'default') {
    try {
      // Check if user is already in this panel
      const { allowed: alreadyActive } = await fgaClient.check({
        user: `user:${userId}`,
        relation: 'active',
        object: `panel_enrollment:${panelId}`,
      });
      
      if (alreadyActive) {
        return false;
      }
      
      // Check if user can claim this panel type
      const { allowed } = await fgaClient.check({
        user: `user:${userId}`,
        relation: 'can_claim',
        object: `panel_enrollment:${panelId}`,
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
      
      // Create panel ownership relationship
      const panelTuple = {
        user: `user:${userId}`,
        relation: 'owner',
        object: `panel:${panelId}`,
      };
      
      await fgaClient.writeTuples([panelTuple]);

      // Create active enrollment relationship
      const enrollmentTuple = {
        user: `user:${userId}`,
        relation: 'active',
        object: `panel_enrollment:${panelId}`,
      };
      
      await fgaClient.writeTuples([enrollmentTuple]);

    } catch (error) {
      console.error('FGA panel claim error:', error);
      throw error;
    }
  }

  /**
   * Leave a panel (remove user from panel)
   * @param {string} userId - User ID (from Auth0)
   * @param {string} panelId - Panel ID to leave
   * @returns {Promise<void>}
   */
  static async leavePanel(userId, panelId) {
    try {

      // Remove panel ownership
      const panelTuple = {
        user: `user:${userId}`,
        relation: 'owner',
        object: `panel:${panelId}`,
      };

      // Remove panel enrollment
      const enrollmentTuple = {
        user: `user:${userId}`,
        relation: 'active',
        object: `panel_enrollment:${panelId}`,
      };

      
      // Use the OpenFGA SDK's deleteTuples method
      await fgaClient.deleteTuples([panelTuple, enrollmentTuple]);

    } catch (error) {
      console.error('FGA panel leave error:', error);
      throw error;
    }
  }

  /**
   * Get user's panel information with detailed panel data
   * @param {string} userId - User ID (from Auth0)
   * @returns {Promise<Object>} - Panel information
   */
  static async getUserPanelInfo(userId) {
    try {
      
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
      
      // Get panel configuration details
      const { getPanelType } = require('./panel-config');
      const detailedPanels = panels.map(panel => {
        const panelId = panel.replace('panel:', '');
        const panelConfig = getPanelType(panelId);
        return {
          id: panelId,
          name: panelConfig?.name || `Panel ${panelId}`,
          description: panelConfig?.description || 'Panel description not available',
          category: panelConfig?.category || 'general',
          icon: panelConfig?.icon || 'fas fa-chart-line',
          color: panelConfig?.color || '#0066CC',
          rewards: panelConfig?.rewards || { base: 5, currency: 'USD' },
          activities: panelConfig?.activities || []
        };
      });
      

      return {
        panels: detailedPanels,
        enrollments,
        hasActivePanel,
        totalPanels: detailedPanels.length
      };
    } catch (error) {
      console.error('FGA get panel info error:', error);
      return {
        panels: [],
        enrollments: [],
        hasActivePanel: false,
        totalPanels: 0
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
