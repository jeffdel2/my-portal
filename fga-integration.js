// FGA Integration for index.js
// Add this after the existing RBAC helper functions

// FGA Helper Functions that work alongside RBAC
const requireFGA = (relation, objectExtractor) => {
  return async (req, res, next) => {
    try {
      // First check RBAC permissions (existing system)
      if (!req.oidc || !req.oidc.user) {
        return res.status(401).json({ error: "Authentication required" });
      }
      
      // Then check FGA permissions (fine-grained)
      const userId = req.oidc.user.sub;
      const object = objectExtractor(req);
      
      if (!object) {
        return res.status(400).json({ error: "Invalid resource" });
      }
      
      const hasPermission = await FGAMiddleware.checkRelationship(userId, relation, object);
      
      if (!hasPermission) {
        return res.status(403).json({ 
          error: "Access denied", 
          message: `You don't have ${relation} permission for this resource`,
          userTier: req.userTier,
          userPermissions: req.userPermissions
        });
      }
      
      next();
    } catch (error) {
      console.error("FGA middleware error:", error);
      res.status(500).json({ error: "Authorization check failed" });
    }
  };
};

// Combined RBAC + FGA middleware
const requireTierAndFGA = (minTier, relation, objectExtractor) => {
  return [requireTier(minTier), requireFGA(relation, objectExtractor)];
};

// FGA Example Routes
const fgaRoutes = `
// FGA Example Routes - demonstrating fine-grained authorization
app.get("/fga-test", requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    
    // Example: Check if user can view a specific document
    const canViewDoc = await FGAMiddleware.checkRelationship(
      userId, 
      "viewer", 
      "document:example-doc-123"
    );
    
    // Example: List all documents user can view
    const userDocuments = await FGAMiddleware.listUserObjects(
      userId, 
      "viewer", 
      "document"
    );
    
    res.json({
      message: "FGA Test Route",
      userId: userId,
      userTier: req.userTier,
      userPermissions: req.userPermissions,
      fgaResults: {
        canViewExampleDoc: canViewDoc,
        userDocuments: userDocuments
      }
    });
  } catch (error) {
    console.error("FGA test error:", error);
    res.status(500).json({ error: "FGA test failed" });
  }
});

// Example route with FGA middleware
app.get("/documents/:id", requiresAuth(), 
  requireFGA("viewer", (req) => \`document:\${req.params.id}\`),
  async (req, res) => {
    res.json({
      message: \`Access granted to document \${req.params.id}\`,
      documentId: req.params.id,
      user: req.oidc.user.sub
    });
  }
);

// Example route combining RBAC + FGA
app.get("/premium-documents/:id", requiresAuth(), 
  requireTier("subscriber"),
  requireFGA("viewer", (req) => \`document:\${req.params.id}\`),
  async (req, res) => {
    res.json({
      message: \`Access granted to premium document \${req.params.id}\`,
      documentId: req.params.id,
      user: req.oidc.user.sub,
      userTier: req.userTier
    });
  }
);
`;

module.exports = { requireFGA, requireTierAndFGA, fgaRoutes };
