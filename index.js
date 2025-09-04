const purchases = [
	{
		date: new Date(),
		description: 'Purchase from Pencils paid via Okta Bank',
		value: 102,
	},
	{
		date: new Date(),
		description: 'Purchase from Pencils paid via Okta Bank',
		value: 42,
	},
]

async function updateProfileWithMFA() {
  try {
    // Step 1: Trigger MFA challenge
    const mfaResponse = await fetch('/trigger-mfa', { method: 'POST' });
    if (!mfaResponse.ok) throw new Error('MFA challenge failed.');

    // Step 2: Submit the profile form
    document.getElementById('profileForm').submit();
  } catch (error) {
    alert('MFA is required to update your profile.');
    console.error('MFA Error:', error);
  }
}


require('dotenv').config();
// FGA Integration
const { FGAMiddleware } = require("./fga-middleware");
const { RBACFGABridge } = require("./fga-rbac-bridge");


//console.log("ENV",process.env);

console.log("MGMT URL", process.env.MGMT_BASE_URL)
console.log("MGMT ID", process.env.MGMT_CLIENT_ID)

  async function getManagementApiToken() {
  try {
    const response = await axios.post(`${process.env.MGMT_BASE_URL}/oauth/token`, {
      client_id: process.env.MGMT_CLIENT_ID,
      client_secret: process.env.MGMT_CLIENT_SECRET,
      audience: `${process.env.MGMT_BASE_URL}/api/v2/`,
      grant_type: 'client_credentials',
    });
    return response.data.access_token;
  } catch (error) {
    console.error('Standalone error minting Management API token:', error.message);
    throw error;
  }
}

const PORT = process.env.PORT || 3000

const express = require('express')
const cors = require('cors')({ origin: true })
const morgan = require('morgan')
const logger = require('./winston')
const axios = require('axios')
const bodyParser = require('body-parser')
// const slideout = require('./public/js/slideout.js')

// add-ons for the front end
const session = require('express-session')
const createError = require('http-errors')
const cookieParser = require('cookie-parser')
const path = require('path')
const { auth, requiresAuth } = require('express-openid-connect')
const { Issuer } = require('openid-client')
const { JWK } = require('node-jose')

//var privateKey = process.env.PVT_KEY.replace(/\\n/g, "\n")
var keystore = JWK.createKeyStore()
var auth0Issuer
var client

const responseType = 'code'
const responseTypesWithToken = ['code id_token', 'code']

const authConfig = {
	secret: process.env.SESSION_SECRET,
	authRequired: false,
	auth0Logout: true,
	baseURL: process.env.APP_URL,
	issuerBaseURL: process.env.ISSUER_BASE_URL,
	clientID: process.env.CLIENT_ID,
	clientSecret: process.env.CLIENT_SECRET,
	authorizationParams: {
		response_type: process.env.RESPONSE_TYPE,
		audience: process.env.AUDIENCE,
		scope: process.env.SCOPE,
	},
}

console.log("AUTHCONFIG",authConfig);

//add-ons for header based authN
const { header, validationResult } = require('express-validator');

const attributes = [
    {"id":"user_email","description":"User email"},
    {"id":"okta_user","description":"Username"},
    {"id":"first_name","description":"First Name"},
    {"id":"last_name","description":"Last Name"},
    {"id":"ldap_category","description":"Category"},
    {"id":"ldap_address","description":"Address"},
    {"id":"device","description":"Device State"},
    {"id":"amr","description":"Authentication Context"},
    {"id":"groups","description":"User groups separated by collon (:), typically taken from the LDAP or AD"},
    {"id":"host","description":"Application Host"},
  ];

const app = express()
app.use(cors)

// new stuff for the front end
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'pug')
app.use('/static', express.static('public'))
app.use(auth(authConfig))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(
	session({
		secret: process.env.SESSION_SECRET,
		resave: false,
		saveUninitialized: true,
	})
)

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(
	morgan('":method :url :status :res[content-length] - :response-time ms"', {
		stream: logger.stream,
	})
)

// RBAC Middleware to process permissions from access token (runs on all routes)
app.use(async (req, res, next) => {
  try {
    // Default values for unauthenticated users
    let permissions = [];
    let userTier = 'free';
    
    // Only process permissions if user is authenticated
    if (req.oidc && req.oidc.accessToken && req.oidc.accessToken.access_token) {
      try {
        const accessTokenParts = req.oidc.accessToken.access_token.split('.');
        if (accessTokenParts.length === 3) {
          const payload = accessTokenParts[1];
          const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8');
          const tokenPayload = JSON.parse(decodedPayload);
          permissions = tokenPayload.permissions || [];
        }
      } catch (error) {
        console.error('Error decoding access token for permissions:', error);
      }
      
      // Permissions come from the access token via Auth0 Roles and Permissions
      // No need to check app_metadata as permissions are managed through Auth0's RBAC system
      
      // Determine user tier based on permissions
      if (permissions.includes('read:premium')) {
        userTier = 'premium';
      } else if (permissions.includes('read:sub')) {
        userTier = 'subscriber';
      }
      
      // Set up FGA tier permissions for authenticated users
      if (req.oidc.user && req.oidc.user.sub) {
        try {
          await RBACFGABridge.updateUserTierPermissions(req.oidc.user.sub, userTier);
          console.log(`FGA tier permissions updated for user ${req.oidc.user.sub} with tier ${userTier}`);
        } catch (fgaError) {
          console.error('Error updating FGA tier permissions:', fgaError);
          // Don't fail the request if FGA setup fails, just log the error
        }
      }
    }
    
    // Add RBAC info to request object
    req.userPermissions = permissions;
    req.userTier = userTier;
    
    // Add to res.locals for use in templates
    res.locals.userPermissions = permissions;
    res.locals.userTier = userTier;
    
    next();
  } catch (error) {
    console.error('Error in RBAC middleware:', error);
    // Default to free tier on error
    req.userPermissions = [];
    req.userTier = 'free';
    res.locals.userPermissions = [];
    res.locals.userTier = 'free';
    next();
  }
})

// RBAC Helper Functions
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.userPermissions.includes(permission)) {
      return res.status(403).render('error', {
        message: 'Access denied. You need higher permissions to access this feature.',
        user: req.oidc && req.oidc.user,
        userTier: req.userTier
      });
    }
    next();
  };
};

const requireTier = (minTier) => {
  const tierLevels = { 'free': 0, 'subscriber': 1, 'premium': 2 };
  return (req, res, next) => {
    const userLevel = tierLevels[req.userTier] || 0;
    const requiredLevel = tierLevels[minTier] || 0;
    
    if (userLevel < requiredLevel) {
      return res.status(403).render('error', {
        message: `Access denied. This feature requires ${minTier} tier or higher.`,
        user: req.oidc && req.oidc.user,
        userTier: req.userTier
      });
    }
    next();
  };
};
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


app.get('/', async (req, res, next) => {
	
  try {

		res.render('landing', {
			user: req.oidc && req.oidc.user,
		})
	} catch (err) {
		console.log(err)
		next(err)
	}
})

app.get('/debug-rbac', (req, res) => {
  console.log('Debug RBAC route accessed');
  console.log('req.oidc:', !!req.oidc);
  console.log('req.userTier:', req.userTier);
  console.log('req.userPermissions:', req.userPermissions);
  
  res.json({
    isAuthenticated: !!req.oidc,
    user: req.oidc ? req.oidc.user : null,
    userTier: req.userTier,
    userPermissions: req.userPermissions,
    hasAccessToken: !!(req.oidc && req.oidc.accessToken),
    accessTokenExists: !!(req.oidc && req.oidc.accessToken && req.oidc.accessToken.access_token)
  });
});

app.get('/test', (req, res) => {
  res.json({ message: 'Test route working', path: req.path });
});

app.get('/test-upgrade', requiresAuth(), async (req, res) => {
  try {
    const token = await getManagementApiToken();
    const userId = req.oidc.user.sub;
    
    // Get current user data
    const userResponse = await axios.get(
      `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    
    // Get user's roles
    const rolesResponse = await axios.get(
      `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}/roles`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    
    res.json({
      userId: userId,
      currentTier: req.userTier,
      currentPermissions: req.userPermissions,
      userRoles: rolesResponse.data,
      userMetadata: userResponse.data.user_metadata
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

app.get('/upgrade-success', requiresAuth(), async (req, res) => {
  res.render('upgrade-success', {
    user: req.oidc && req.oidc.user,
    userTier: req.userTier,
    userPermissions: req.userPermissions
  });
});
// FGA Example Routes - demonstrating fine-grained authorization
app.get("/fga-test", requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const userTier = req.userTier;
    
    // Test tier-based permissions using the tier_permission type
    const tierChecks = {
      canAccessFree: await FGAMiddleware.checkRelationship(
        userId, 
        "can_access_free", 
        "tier_permission:global"
      ),
      canAccessSubscriber: await FGAMiddleware.checkRelationship(
        userId, 
        "can_access_subscriber", 
        "tier_permission:global"
      ),
      canAccessPremium: await FGAMiddleware.checkRelationship(
        userId, 
        "can_access_premium", 
        "tier_permission:global"
      )
    };
    
    // Test document permissions
    const documentChecks = {
      canViewExampleDoc: await FGAMiddleware.checkRelationship(
        userId, 
        "can_view", 
        "document:example-doc-123"
      ),
      canEditExampleDoc: await FGAMiddleware.checkRelationship(
        userId, 
        "can_edit", 
        "document:example-doc-123"
      ),
      canDeleteExampleDoc: await FGAMiddleware.checkRelationship(
        userId, 
        "can_delete", 
        "document:example-doc-123"
      )
    };
    
    // List all documents user can view
    const userDocuments = await FGAMiddleware.listUserObjects(
      userId, 
      "can_view", 
      "document"
    );
    
    // List all tier permissions user has
    const userTierPermissions = await FGAMiddleware.listUserObjects(
      userId, 
      "can_access_free", 
      "tier_permission"
    );
    
    // Validate tier consistency between RBAC and FGA
    const validateTierConsistency = (userTier, tierChecks) => {
      const expectedAccess = {
        'free': { free: true, subscriber: false, premium: false },
        'subscriber': { free: true, subscriber: true, premium: false },
        'premium': { free: true, subscriber: true, premium: true }
      };
      
      const expected = expectedAccess[userTier] || expectedAccess['free'];
      
      return {
        tier: userTier,
        expected: expected,
        actual: {
          free: tierChecks.canAccessFree,
          subscriber: tierChecks.canAccessSubscriber,
          premium: tierChecks.canAccessPremium
        },
        isConsistent: (
          tierChecks.canAccessFree === expected.free &&
          tierChecks.canAccessSubscriber === expected.subscriber &&
          tierChecks.canAccessPremium === expected.premium
        )
      };
    };
    
    res.json({
      message: "FGA Test Route with Tier Validation",
      userId: userId,
      userTier: userTier,
      userPermissions: req.userPermissions,
      fgaResults: {
        tierValidation: {
          currentTier: userTier,
          tierChecks: tierChecks,
          userTierPermissions: userTierPermissions
        },
        documentPermissions: documentChecks,
        userDocuments: userDocuments,
        tierAnalysis: validateTierConsistency(userTier, tierChecks)
      }
    });
  } catch (error) {
    console.error("FGA test error:", error);
    res.status(500).json({ error: "FGA test failed" });
  }
});
// Route to set up user's tier permissions in FGA
app.post("/setup-fga-tier", requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const userTier = req.userTier;
    
    // Set up tier permissions in FGA
    await RBACFGABridge.setupUserTierPermissions(userId, userTier);
    
    res.json({
      message: "FGA tier permissions set up successfully",
      userId: userId,
      userTier: userTier,
      fgaSetup: {
        tierPermission: `tier_permission:global`,
        relationships: [
          `user:${userId} ${userTier}_tier tier_permission:global`
        ]
      }
    });
  } catch (error) {
    console.error("Error setting up FGA tier permissions:", error);
    res.status(500).json({ error: "Failed to set up FGA tier permissions" });
  }
});

// Route to check and sync RBAC with FGA
app.get("/sync-rbac-fga", requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const userTier = req.userTier;
    const userPermissions = req.userPermissions;
    
    // Check current FGA tier permissions
    const currentTierChecks = {
      canAccessFree: await FGAMiddleware.checkRelationship(
        userId, 
        "can_access_free", 
        "tier_permission:global"
      ),
      canAccessSubscriber: await FGAMiddleware.checkRelationship(
        userId, 
        "can_access_subscriber", 
        "tier_permission:global"
      ),
      canAccessPremium: await FGAMiddleware.checkRelationship(
        userId, 
        "can_access_premium", 
        "tier_permission:global"
      )
    };
    
    // Determine if sync is needed
    const expectedTier = userTier;
    const needsSync = !currentTierChecks[`canAccess${expectedTier.charAt(0).toUpperCase() + expectedTier.slice(1)}`];
    
    if (needsSync) {
      // Set up tier permissions in FGA
      await RBACFGABridge.setupUserTierPermissions(userId, userTier);
    }
    
    res.json({
      message: "RBAC-FGA sync check completed",
      userId: userId,
      rbacInfo: {
        userTier: userTier,
        userPermissions: userPermissions
      },
      fgaInfo: {
        currentTierChecks: currentTierChecks,
        needsSync: needsSync,
        synced: needsSync
      }
    });
  } catch (error) {
    console.error("Error syncing RBAC with FGA:", error);
    res.status(500).json({ error: "Failed to sync RBAC with FGA" });
  }
});


// Example route with FGA middleware
app.get("/documents/:id", requiresAuth(), 
  requireFGA("viewer", (req) => `document:${req.params.id}`),
  async (req, res) => {
    res.json({
      message: `Access granted to document ${req.params.id}`,
      documentId: req.params.id,
      user: req.oidc.user.sub
    });
  }
);

// Example route combining RBAC + FGA
app.get("/premium-documents/:id", requiresAuth(), 
  requireTier("subscriber"),
  requireFGA("viewer", (req) => `document:${req.params.id}`),
  async (req, res) => {
    res.json({
      message: `Access granted to premium document ${req.params.id}`,
      documentId: req.params.id,
      user: req.oidc.user.sub,
      userTier: req.userTier
    });
  }
);
// RBAC + FGA Integration Examples

// Route that demonstrates tier-based access with FGA
app.get("/my-documents", requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const userTier = req.userTier;
    
    // List all documents user can view (combines RBAC tier + FGA permissions)
    const userDocuments = await FGAMiddleware.listUserObjects(
      userId, 
      "can_view", 
      "document"
    );
    
    res.json({
      message: "Your accessible documents",
      userId: userId,
      userTier: userTier,
      documents: userDocuments,
      tierInfo: {
        canCreateDocuments: userTier !== 'free',
        canEditDocuments: ['subscriber', 'premium'].includes(userTier),
        canDeleteDocuments: userTier === 'premium'
      }
    });
  } catch (error) {
    console.error("Error fetching user documents:", error);
    res.status(500).json({ error: "Failed to fetch documents" });
  }
});

// Route that creates a document with proper FGA relationships
app.post("/documents", requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const userTier = req.userTier;
    const { title, content } = req.body;
    
    // Check RBAC tier permission
    if (userTier === 'free') {
      return res.status(403).json({ 
        error: "Upgrade required", 
        message: "Free tier users cannot create documents. Please upgrade to subscriber or premium." 
      });
    }
    
    // Create document (in real app, this would save to database)
    const documentId = 'doc_' + Date.now();
    
    // Set up FGA relationships for the new document
    await RBACFGABridge.createResourceOwnership(userId, 'document', documentId);
    
    res.json({
      message: "Document created successfully",
      documentId: documentId,
      title: title,
      owner: userId,
      userTier: userTier
    });
  } catch (error) {
    console.error("Error creating document:", error);
    res.status(500).json({ error: "Failed to create document" });
  }
});

// Route that demonstrates sharing with FGA
app.post("/documents/:id/share", requiresAuth(), 
  requireFGA("can_share", (req) => 'document:' + req.params.id),
  async (req, res) => {
    try {
      const ownerId = req.oidc.user.sub;
      const documentId = req.params.id;
      const { shareWithEmail, permission = 'viewer' } = req.body;
      
      // In a real app, you'd look up the user by email
      // For demo purposes, we'll use a mock user ID
      const shareWithUserId = 'user_' + shareWithEmail.replace('@', '_');
      
      await RBACFGABridge.shareResource(
        ownerId, 
        shareWithUserId, 
        'document', 
        documentId, 
        permission
      );
      
      res.json({
        message: "Document shared successfully",
        documentId: documentId,
        sharedWith: shareWithEmail,
        permission: permission
      });
    } catch (error) {
      console.error("Error sharing document:", error);
      res.status(500).json({ error: "Failed to share document" });
    }
  }
);

// Route that demonstrates combined RBAC + FGA access control
app.get("/documents/:id", requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const userTier = req.userTier;
    const documentId = req.params.id;
    
    // Check both RBAC tier and FGA permissions
    const hasAccess = await RBACFGABridge.checkResourceAccess(
      userId, 
      userTier, 
      'document', 
      documentId, 
      'view'
    );
    
    if (!hasAccess) {
      return res.status(403).json({ 
        error: "Access denied",
        message: "You don't have permission to view this document",
        userTier: userTier
      });
    }
    
    res.json({
      message: "Document access granted",
      documentId: documentId,
      userTier: userTier,
      accessLevel: "viewer"
    });
  } catch (error) {
    console.error("Error accessing document:", error);
    res.status(500).json({ error: "Failed to access document" });
  }
});


/*
app.get('/access', async (req, res) => {
  console.log("ACCESS ERROR", req)
  res.render('access', {
	  user: req.oidc && req.oidc.user,
    access: req.oidc.user.access_granted,
	})
})
*/

app.get('/user', requiresAuth(), async (req, res) => {
	res.render('user', {
		user: req.oidc && req.oidc.user,
		id_token: req.oidc && req.oidc.idToken,
		access_token: req.oidc && req.oidc.accessToken,
		refresh_token: req.oidc && req.oidc.refreshToken,
    first: req.oidc.user.first_name,
	})
})

app.get('/tokens', requiresAuth(), async (req, res) => {
	// Decode JWT tokens to display their contents
	let idTokenPayload = null;
	let accessTokenPayload = null;
	
	try {
		if (req.oidc.idToken) {
			const idTokenParts = req.oidc.idToken.split('.');
			if (idTokenParts.length === 3) {
				const payload = idTokenParts[1];
				const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8');
				idTokenPayload = JSON.parse(decodedPayload);
			}
		}
	} catch (error) {
		console.error('Error decoding ID token:', error);
	}
	
	try {
		if (req.oidc.accessToken && req.oidc.accessToken.access_token) {
			const accessTokenParts = req.oidc.accessToken.access_token.split('.');
			if (accessTokenParts.length === 3) {
				const payload = accessTokenParts[1];
				const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8');
				accessTokenPayload = JSON.parse(decodedPayload);
			}
		}
	} catch (error) {
		console.error('Error decoding access token:', error);
	}
	
	res.render('tokens', {
		user: req.oidc && req.oidc.user,
		id_token: req.oidc && req.oidc.idToken,
		access_token: req.oidc && req.oidc.accessToken,
		refresh_token: req.oidc && req.oidc.refreshToken,
		id_token_payload: idTokenPayload,
		access_token_payload: accessTokenPayload,
	})
})

app.get('/upgrade', requiresAuth(), async (req, res) => {
  // Only allow free tier users to access upgrade page
  if (req.userTier !== 'free') {
    return res.redirect('/');
  }
  
  res.render('upgrade', {
    user: req.oidc && req.oidc.user,
    userTier: req.userTier,
    userPermissions: req.userPermissions
  });
});

app.post('/upgrade', requiresAuth(), async (req, res) => {
  // Only allow free tier users to upgrade
  if (req.userTier !== 'free') {
    return res.status(403).send('Already upgraded');
  }
  
  const { tier } = req.body;
  
  if (!['subscriber', 'premium'].includes(tier)) {
    return res.status(400).send('Invalid tier selected');
  }
  
  try {
    // Here you would typically integrate with your payment processor
    // and then update the user's permissions via Auth0 Management API
    
    const token = await getManagementApiToken();
    const userId = req.oidc.user.sub;
    
    // Define role IDs based on tier (you'll need to get these from your Auth0 dashboard)
    let roleId = '';
    if (tier === 'subscriber') {
      roleId = process.env.SUBSCRIBER_ROLE_ID; // Add this to your .env file
    } else if (tier === 'premium') {
      roleId = process.env.PREMIUM_ROLE_ID; // Add this to your .env file
    }
    
    if (!roleId) {
      throw new Error(`Role ID not configured for tier: ${tier}`);
    }
    
    // Remove the free role first
    const freeRoleId = process.env.FREE_ROLE_ID;
    if (freeRoleId) {
      try {
        await axios.delete(
          `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}/roles`,
          {
            data: {
              roles: [freeRoleId]
            },
            headers: { Authorization: `Bearer ${token}` },
          }
        );
        console.log(`Removed free role from user ${userId}`);
      } catch (error) {
        console.log(`User ${userId} may not have had the free role, or it was already removed`);
      }
    }
    
    // Assign new role to user
    await axios.post(
      `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}/roles`,
      {
        roles: [roleId]
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    
    // Update user metadata to track the upgrade
    await axios.patch(
      `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`,
      {
        user_metadata: {
          upgrade_requested: tier,
          upgrade_date: new Date().toISOString()
        }
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    
    console.log(`User ${userId} upgraded to ${tier} tier with role: ${roleId}`);
    
    // Update FGA tier permissions for the upgraded user
    try {
      await RBACFGABridge.updateUserTierPermissions(userId, tier);
      console.log(`FGA tier permissions updated for user ${userId} to ${tier} tier`);
    } catch (fgaError) {
      console.error('Error updating FGA tier permissions during upgrade:', fgaError);
      // Don't fail the upgrade if FGA update fails, just log the error
    }
    
    // Store upgrade info in session for the success page
    req.session.upgradeInfo = {
      tier: tier,
      upgradedAt: new Date().toISOString()
    };
    
    // Trigger a fresh authorization flow to get new tokens with updated permissions
    // This will redirect to Auth0 and then back to the success page
    res.oidc.login({
      returnTo: '/upgrade-success',
      prompt: 'consent'
    });
    
  } catch (error) {
    console.error('Error processing upgrade:', error);
    if (error.response) {
      console.error('Auth0 API Error:', error.response.data);
    }
    res.status(500).send('Error processing upgrade request');
  }
});


app.get('/profile_old', requiresAuth(), async (req, res) => {
    try {
    const token = await getManagementApiToken()
    const userId = req.oidc.user.sub;
    const response = await axios.get(`${ISSUER_BASE_URL}/api/v2/users/${userId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.locals.user = response.data;
  } catch (error) {
    console.error('Error fetching user data:', error.message);
    res.locals.user = req.oidc.user;
  }
  res.render('profile2', { user: res.locals.user });
});

app.get('/profile', requiresAuth(), async (req, res) => {
  try {
    // Define the URLs for the two APIs you want to call
    const token = await getManagementApiToken()
    const userId = req.oidc.user.sub;
    const authz_header = { Authorization: `Bearer ${token}` };
    
    const url1 = `${process.env.ISSUER_BASE_URL}/api/v2/users/${userId}`;
    const url2 = `${process.env.ISSUER_BASE_URL}/api/v2/users/${userId}/authentication-methods`;

    console.log('Initiating API calls...');

    // Use Promise.all to make concurrent requests
    // axios.get() returns a promise
    const [response1, response2] = await Promise.all([
      axios.get(url1, { headers: authz_header }),
      axios.get(url2, { headers: authz_header })
    ]);

    console.log('Both API calls completed successfully!');

    // You can now access the data from each response
    res.locals.user = response1.data;
    res.locals.factors = response2.data;
    
  } catch (error) {
    console.error('Error fetching data from one or more APIs:');
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
      console.error('Headers:', error.response.headers);
    } else if (error.request) {
      // The request was made but no response was received
      console.error('Request Error:', error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error('Error Message:', error.message);
    }
  }
  const clientId = `${process.env.CLIENT_ID}`;
  const mgmtUrl = `${process.env.MGMT_BASE_URL}`;
  const issuerUrl = `${process.env.ISSUER_BASE_URL}`;
  const appUrl = `${process.env.APP_URL}`;
  res.render('profile2', 
	{ user: res.locals.user, 
	  factors: res.locals.factors, 
	  clientId, 
	  issuerUrl, 
	  mgmtUrl, 
	  appUrl
	});
});


// Handle profile updates
app.post('/profile', requiresAuth(), async (req, res) => {
  const userId = req.oidc.user.sub;
  const { name, email, first_name, last_name, consents } = req.body;
  const sanitizedConsents = Array.isArray(consents) ? consents.filter(Boolean) : [];

  try {
    const token = await getManagementApiToken()
    
    /* Step 1: Trigger MFA Challenge
    const mfaChallengeResponse = await axios.post(
      `${ISSUER_BASE_URL}/mfa/challenge`,
      {
        client_id: CLIENT_ID,
        user_id: userId,
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    // The MFA challenge is sent; now await user confirmation.
    const mfaToken = mfaChallengeResponse.data.mfa_token;
    */
    
    // Fetch current user data
    const userResponse = await axios.get(`${process.env.ISSUER_BASE_URL}/api/v2/users/${userId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    
    const currentMetadata = userResponse.data.user_metadata || {};
    
    // Merge existing metadata with new updates
    const updatedMetadata = {
      //...currentMetadata.consents,
      consents: sanitizedConsents || "",
      first_name: first_name || "",
      last_name: last_name || ""
    };
    
    // Merge existing core attributes with new updates
    //const updatedGivenName = given_name || null;
    //const updatedFamilyName = family_name || null;
    
    console.log('Payload to Auth0:', {
      user_metadata: { ...currentMetadata, consents: sanitizedConsents },
      email
      });
    
    // Update user metadata via Auth0 Management API
    await axios.patch(
      `${process.env.ISSUER_BASE_URL}/api/v2/users/${userId}`,
      {
        user_metadata: updatedMetadata,
        email,// Optional: Update email in root profile (if allowed)
        name,
        //given_name: updatedGivenName,
        //family_name: updatedFamilyName
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    res.redirect('/profile');
  } catch (error) {
    console.error('Error updating user data:', error.message);
    res.status(500).send('Error updating profile.');
  }
});


app.get('/dashboard', requiresAuth(), (req, res) => {
  res.render('dashboard', {
    isAdmin: req.userRoles.includes('admin'), // Check if user is an admin
    isUser: req.userRoles.includes('user'),  // Check if user is a non-admin
  });
});

app.get('/portal', requiresAuth(), async (req, res) => {
    try {
    const token = await getManagementApiToken()
    const userId = req.oidc.user.sub;
    const response = await axios.get(`${process.env.ISSUER_BASE_URL}/api/v2/users/${userId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.locals.user = response.data;
  } catch (error) {
    console.error('Error fetching user data:', error.message);
    res.locals.user = req.oidc.user;
  }
  res.render('portal', { user: res.locals.user });
  console.log('Res sent to template:', res.locals.user);
});


app.post('/trigger-mfa', requiresAuth(), async (req, res) => {
  const userId = req.oidc.user.sub;

  try {
    const token = await getManagementApiToken();

    // Trigger MFA Challenge
    const response = await axios.post(
      `${process.env.ISSUER_BASE_URL}/mfa/challenge`,
      {
        client_id: process.env.CLIENT_ID,
        user_id: userId,
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    res.status(200).send('MFA challenge sent successfully.');
  } catch (error) {
    console.error('Error triggering MFA:', error.response?.data || error.message);
    res.status(500).send('Error triggering MFA.');
  }
});



app.get('/headers', async (req, res) => {
  console.log("REQUEST  ",req.headers.host)
	res.render('headers', {
		host: req.headers.host,
	})
})

app.get('/cart', requiresAuth(), async (req, res) => {
	let errorMessage
	const error = req.query && req.query.error
	if (error === 'access_denied') {
		// The AS said we are not allowed to do this transaction, tell the end-user!
		errorMessage =
			'You are not authorized to make this transaction. Perhaps you can try with a smaller transaction amount?'
		delete req.session.pendingTransaction
	}

	res.render('cart', {
		user: req.oidc && req.oidc.user,
		id_token: req.oidc && req.oidc.idToken,
		access_token: req.oidc && req.oidc.accessToken,
		refresh_token: req.oidc && req.oidc.refreshToken,
		errorMessage,
	})
})

app.get('/prepare-transaction', requiresAuth(), async (req, res) => {
	let errorMessage
	const error = req.query && req.query.error
	if (error === 'access_denied') {
		// The AS said we are not allowed to do this transaction, tell the end-user!
		errorMessage =
			'You are not authorized to make this transaction. Perhaps you can try with a smaller transaction amount?'
		delete req.session.pendingTransaction
	}

	const transaction_amount = (req.query && req.query.transaction_amount) || 15
	res.render('transaction', {
		user: req.oidc && req.oidc.user,
		id_token: req.oidc && req.oidc.idToken,
		access_token: req.oidc && req.oidc.accessToken,
		refresh_token: req.oidc && req.oidc.refreshToken,
		transaction_amount,
		errorMessage,
	})
})

app.get('/resume-transaction', requiresAuth(), async (req, res, next) => {
	const tokenSet = await client.callback(
		BANK_REDIRECT_URI,
		{ code: req.query.code },
		{ nonce: '132123' }
	)
	console.log(`Token set: ${tokenSet}`)

	if (req.session.pendingTransaction) {
		console.log(
			'Processing pending transaction',
			req.session.pendingTransaction
		)
		try {
			const { type, amount, from, to } = req.session.pendingTransaction
			// TODO: handle the error case here...
			submitTransaction({ type, amount, from, to }, req)
			res.redirect('/transaction-complete')
		} catch (err) {
			console.log('refused to connect')
			console.log(err.stack)
			return next(err)
		}
	} else {
		const transaction_amount = (req.query && req.query.amount) || 15
		res.render('transaction', {
			user: req.oidc && req.oidc.user,
			id_token: req.oidc && req.oidc.idToken,
			access_token: req.oidc && req.oidc.accessToken,
			refresh_token: req.oidc && req.oidc.refreshToken,
			transaction_amount,
		})
	}
})

app.get('/transaction-complete', requiresAuth(), async (req, res) => {
	res.render('transaction-complete', {
		user: req.oidc && req.oidc.user,
	})
})

const submitTransaction = (payload, req) => {
	const type = payload.type
	const transferFrom = payload.from
	const transferTo = payload.to
	const amount = payload.amount

	purchases.push({
		date: new Date(),
		description: `${type} from ${transferTo} paid via ${transferFrom}`,
		value: amount,
	})

	delete req.session.pendingTransaction
}

app.post('/submit-transaction', requiresAuth(), async (req, res, next) => {
	const type = req.body.type
	const amount = Number(req.body.amount)
	const transferFrom = req.body.transferFrom
	const transferTo = req.body.transferTo
	try {
		if (responseTypesWithToken.includes(RESPONSE_TYPE)) {
			const authorization_details = [
				{
					type: type,
					amount: amount,
					from: transferFrom,
					to: transferTo,
				},
			]

			req.session.pendingTransaction = {
				type: type,
				amount: amount,
				from: transferFrom,
				to: transferTo,
			}

			const authorization_request = {
				audience: BANK_AUDIENCE,
				scope: `openid profile ${BANK_AUD_SCOPES}`,
				nonce: '132123',
				response_type: responseType,
				authorization_details: JSON.stringify(authorization_details),
			}
			console.log('authZ', authorization_request)

			const response = await client.pushedAuthorizationRequest(
				authorization_request
			)
			console.log('PAR response', response)

			res.redirect(
				`${BANK_ISSUER}/authorize?client_id=${process.env.BANK_CLIENT_ID}&request_uri=${response.request_uri}`
			)

			return
		} else {
			next(
				createError(
					403,
					'Access token required to complete this operation. Please, use an OIDC flow that issues an access_token'
				)
			)
		}
	} catch (err) {
		next(err)
	}
})

app.get('/balance', requiresAuth(), requireTier('subscriber'), async (req, res, next) => {
	try {
		if (responseTypesWithToken.includes(RESPONSE_TYPE)) {
			let totalPurchases = purchases.reduce(
				(accum, purchase) => accum + purchase.value,
				0
			)

			res.render('balance', {
				user: req.oidc && req.oidc.user,
				balance: totalPurchases,
				purchases: purchases,
				userTier: req.userTier,
				userPermissions: req.userPermissions
			})
		} else {
			next(
				createError(
					403,
					'Access token required to complete this operation. Please, use an OIDC flow that issues an access_token'
				)
			)
		}
	} catch (err) {
		next(err)
	}
})

app.get('/api', (request, response) => {
	response.status(200).end('OK')
})

app.get('/api/timestamp', (request, response) => {
	response.send(`${Date.now()}`)
})

// catch 404 and forward to error handler
//app.use((req, res, next) => {
//	next(createError(404))
//})

// Catch-all middleware for authenticated routes (but not for debug routes)
app.use(async (req, res, next) => {
  // Skip this middleware for debug routes
  if (req.path === '/debug-rbac' || req.path === '/test') {
    return next();
  }
  
  // Only apply to authenticated routes
  if (req.oidc && req.oidc.user) {
    try {
      const token = await getManagementApiToken()
      const userId = req.oidc.user.sub;
      const response = await axios.get(`${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      res.locals.user = response.data;
    } catch (error) {
      console.error('Error fetching user data:', error.message);
      res.locals.user = req.oidc.user;
    }
  }
  next();
});

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ error: 'Route not found', path: req.path });
});

/*
app.use((err, req, res, next) => {
  if (err && err.error === 'access_denied') {
    console.log(err);
    //return res.status(403).send(err.error_description);
    
    return res.redirect('/access');
  }
	next(createError(404))
})
*/

app.listen(PORT, () => {
	console.log(`App listening on port ${PORT}`)
})

module.exports = app
