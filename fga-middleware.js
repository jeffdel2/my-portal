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
}

module.exports = { FGAMiddleware };
