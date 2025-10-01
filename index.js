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

// testing branch check in

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

// Partners-specific Auth0 configuration (same client, different organization context)
const partnersAuthConfig = {
	secret: process.env.SESSION_SECRET,
	authRequired: false,
	auth0Logout: true,
	baseURL: process.env.APP_URL,
	issuerBaseURL: process.env.ISSUER_BASE_URL,
	clientID: process.env.CLIENT_ID, // Same client ID
	clientSecret: process.env.CLIENT_SECRET, // Same client secret
	authorizationParams: {
		response_type: process.env.RESPONSE_TYPE,
		audience: process.env.AUDIENCE,
		scope: process.env.SCOPE,
		// Organization context will be added dynamically in the login route
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

// Custom callback handler to check for MFA return (must be before auth middleware)
app.get('/callback', (req, res, next) => {
  // Check if this is a return from our MFA flow
  if (req.session && req.session.mfaReturnTo) {
    const returnTo = req.session.mfaReturnTo;
    delete req.session.mfaReturnTo;
    console.log('MFA flow completed, redirecting to:', returnTo);
    return res.redirect(returnTo);
  }
  
  // Otherwise, use the default callback handling
  next();
});

// Customer Auth0 middleware
app.use(auth(authConfig))

// Partners Auth0 middleware (for organization-specific routes)
const partnersAuth = auth(partnersAuthConfig)

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
      
      console.log('RBAC Middleware - User permissions:', permissions);
      console.log('RBAC Middleware - User ID:', req.oidc.user?.sub);
      console.log('RBAC Middleware - Access token exists:', !!req.oidc.accessToken);
      console.log('RBAC Middleware - ID token exists:', !!req.oidc.idToken);
      console.log('RBAC Middleware - Organization context:', {
        orgId: req.oidc.idTokenClaims?.org_id,
        orgName: req.oidc.idTokenClaims?.org_name
      });
      
      // Determine user tier based on permissions
      if (permissions.includes('sub:premium')) {
        userTier = 'premium';
      } else if (permissions.includes('sub:basic')) {
        userTier = 'subscriber';
      } else if (permissions.includes('org:admin')) {
        userTier = 'org-admin';
      } else if (permissions.includes('org:user')) {
        userTier = 'org-user';
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

app.get('/partners', async (req, res, next) => {
	try {
		res.render('partners-landing', {
			title: 'Partner Portal',
			user: req.oidc && req.oidc.user,
			userTier: req.userTier,
			userPermissions: req.userPermissions
		})
	} catch (err) {
		console.log(err)
		next(err)
	}
})

// Partners registration page
app.get('/partners/register', (req, res) => {
	res.render('partners-register', {
		title: 'Partner Portal',
		user: req.oidc && req.oidc.user,
		userTier: req.userTier,
		userPermissions: req.userPermissions,
		formData: req.session.registrationFormData || {},
		success: req.query.success === 'true',
		error: req.query.error
	})
})

// Handle partners registration form submission
app.post('/partners/register', async (req, res) => {
	try {
		const {
			orgName,
			orgDomain,
			contactFirstName,
			contactLastName,
			contactEmail,
			agreeTerms,
			agreePrivacy,
			agreeMarketing
		} = req.body;

		// Debug: Log all form data
		console.log('=== PARTNER REGISTRATION DEBUG ===');
		console.log('Raw request body:', JSON.stringify(req.body, null, 2));
		console.log('Parsed form data:', {
			orgName,
			orgDomain,
			contactFirstName,
			contactLastName,
			contactEmail,
			agreeTerms,
			agreePrivacy,
			agreeMarketing
		});
		console.log('=== END DEBUG ===');

		// Validate required fields (only essential fields for org creation)
		if (!orgName || !orgDomain || !contactFirstName || !contactLastName || !contactEmail) {
			req.session.registrationFormData = req.body;
			return res.redirect('/partners/register?error=' + encodeURIComponent('Please fill in all required fields'));
		}

		if (!agreeTerms || !agreePrivacy) {
			req.session.registrationFormData = req.body;
			return res.redirect('/partners/register?error=' + encodeURIComponent('You must agree to the terms and privacy policy'));
		}

		// Get Auth0 Management API token
		const token = await getManagementApiToken();

		// Create Auth0 Organization (minimal payload for testing)
		const organizationData = {
			name: orgName.toLowerCase().replace(/[^a-z0-9-]/g, '-'), // Auth0 requires lowercase, alphanumeric, hyphens only
			display_name: orgName
		};

		// Store metadata separately for debugging (not sent to Auth0)
		const debugMetadata = {
			orgDomain: String(orgDomain || ''),
			contactFirstName: String(contactFirstName || ''),
			contactLastName: String(contactLastName || ''),
			contactEmail: String(contactEmail || ''),
			agreeMarketing: String(agreeMarketing === 'on' ? 'true' : 'false'),
			registrationDate: String(new Date().toISOString())
		};

		console.log('Creating Auth0 organization with data:', JSON.stringify(organizationData, null, 2));
		console.log('Debug metadata (not sent to Auth0):', JSON.stringify(debugMetadata, null, 2));
		console.log('Auth0 Management API URL:', `${process.env.MGMT_BASE_URL}/api/v2/organizations`);
		console.log('Auth0 Management API Token (first 20 chars):', token.substring(0, 20) + '...');

		// Create the organization
		const orgResponse = await axios.post(
			`${process.env.MGMT_BASE_URL}/api/v2/organizations`,
			organizationData,
			{
				headers: { 
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				}
			}
		);

		const organizationId = orgResponse.data.id;
		console.log('Created organization with ID:', organizationId);

		// Create a dedicated connection for this organization
		const connectionName = `${orgName.toLowerCase().replace(/[^a-z0-9-]/g, '-')}-connection`;
		const connectionData = {
			name: connectionName,
			strategy: 'auth0',
			options: {
				passwordPolicy: 'good',
				brute_force_protection: true,
				disable_signup: false,
				requires_username: false
			},
			enabled_clients: [process.env.CLIENT_ID] // Automatically assign to our application
		};

		console.log('Creating Auth0 connection:', JSON.stringify(connectionData, null, 2));
		console.log('Auth0 Connections API URL:', `${process.env.MGMT_BASE_URL}/api/v2/connections`);

		const connectionResponse = await axios.post(
			`${process.env.MGMT_BASE_URL}/api/v2/connections`,
			connectionData,
			{
				headers: { 
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				}
			}
		);

		const connectionId = connectionResponse.data.id;
		console.log('Created connection with ID:', connectionId);

		// Enable the connection for our client
		console.log('Enabling connection for client:', process.env.CLIENT_ID);
		await axios.patch(
			`${process.env.MGMT_BASE_URL}/api/v2/connections/${connectionId}`,
			{
				enabled_clients: [process.env.CLIENT_ID]
			},
			{
				headers: { 
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				}
			}
		);
		console.log('Successfully enabled connection for client');

		// Enable the connection for the organization
		console.log('Enabling connection for organization:', organizationId);
		await axios.post(
			`${process.env.MGMT_BASE_URL}/api/v2/organizations/${organizationId}/enabled_connections`,
			{
				connection_id: connectionId,
				assign_membership_on_login: true,
				show_as_button: true
			},
			{
				headers: { 
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				}
			}
		);
		console.log('Successfully enabled connection for organization');

		// Send member invitation instead of creating user directly
		const invitationData = {
			inviter: {
				name: "AT&T Partner Portal"
			},
			invitee: {
				email: String(contactEmail)
			},
			client_id: process.env.CLIENT_ID, // Same client ID for both flows
			connection_id: connectionId,
			app_metadata: {
				organizationId: String(organizationId),
				organizationName: String(orgName),
				agreeMarketing: String(agreeMarketing === 'on' ? 'true' : 'false'),
				invitedRole: 'org-admin' // Set the intended role for filtering
			},
			user_metadata: {
				firstName: String(contactFirstName),
				lastName: String(contactLastName)
			},
			ttl_sec: 604800, // 7 days
			send_invitation_email: true,
			roles: ['org_admin'], // Assign admin role during invitation
			// Add organization context to the invitation
			organization: {
				id: organizationId,
				name: orgName
			}
		};

		console.log('Sending organization invitation with data:', JSON.stringify(invitationData, null, 2));
		console.log('Auth0 Invitations API URL:', `${process.env.MGMT_BASE_URL}/api/v2/organizations/${organizationId}/invitations`);

		const invitationResponse = await axios.post(
			`${process.env.MGMT_BASE_URL}/api/v2/organizations/${organizationId}/invitations`,
			invitationData,
			{
				headers: { 
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				}
			}
		);

		const invitationId = invitationResponse.data.id;
		console.log('Successfully sent invitation with ID:', invitationId);

		console.log('Successfully created organization and sent invitation');

		// Clear form data from session
		delete req.session.registrationFormData;

		// Redirect to success page
		res.redirect('/partners/register?success=true');

	} catch (error) {
		console.error('Error creating partner organization:', error);
		
		// Store form data in session for re-population
		req.session.registrationFormData = req.body;
		
		let errorMessage = 'An error occurred while creating your organization. Please try again.';
		
		if (error.response) {
			console.error('Auth0 API Error Response:', {
				status: error.response.status,
				statusText: error.response.statusText,
				data: error.response.data,
				headers: error.response.headers
			});
			
			if (error.response.data) {
				errorMessage = error.response.data.message || error.response.data.error_description || errorMessage;
			}
		} else if (error.request) {
			console.error('Auth0 API Request Error:', error.request);
			errorMessage = 'Unable to connect to authentication service. Please try again.';
		} else {
			console.error('General Error:', error.message);
		}
		
		res.redirect('/partners/register?error=' + encodeURIComponent(errorMessage));
	}
})

// Partners-specific login route that redirects back to /partners
app.get('/partners/login', (req, res) => {
	// Use partners-specific login with organization context
	const authorizationParams = {
		// Ensure audience and scope are included for access token generation
		audience: process.env.AUDIENCE,
		scope: process.env.SCOPE
	}
	
	// Only add organization if provided
	if (req.query.organization) {
		authorizationParams.organization = req.query.organization
	}
	
	// Only add connection if provided
	if (req.query.connection) {
		authorizationParams.connection = req.query.connection
	}
	
	// Only add invitation if provided
	if (req.query.invitation) {
		authorizationParams.invitation = req.query.invitation
	}
	
	const loginOptions = {
		returnTo: '/partners',
		authorizationParams: authorizationParams
	}
	
	console.log('Partners login with options:', JSON.stringify(loginOptions, null, 2))
	console.log('Partners login - Environment config:', {
		SCOPE: process.env.SCOPE,
		AUDIENCE: process.env.AUDIENCE,
		RESPONSE_TYPE: process.env.RESPONSE_TYPE
	})
	console.log('Partners login - Query params:', req.query)
	console.log('Partners login - Main authConfig authorizationParams:', authConfig.authorizationParams)
	
	res.oidc.login(loginOptions)
})

// Organization-specific login route for direct access
app.get('/partners/login/:organizationId', (req, res) => {
	const { organizationId } = req.params
	const connectionName = req.query.connection
	
	// Redirect to partners login with organization context
	const redirectUrl = `/partners/login?organization=${organizationId}${connectionName ? `&connection=${connectionName}` : ''}`
	console.log('Redirecting to organization-specific login:', redirectUrl)
	res.redirect(redirectUrl)
})

// Partners-specific tokens page
app.get('/partners/tokens', requiresAuth(), (req, res) => {
	try {
		// Debug: Log what's available in req.oidc
		console.log('Partners tokens page - req.oidc keys:', Object.keys(req.oidc))
		console.log('Partners tokens page - req.oidc.accessToken:', req.oidc.accessToken)
		console.log('Partners tokens page - req.oidc.accessToken.access_token:', req.oidc.accessToken?.access_token)
		
		// Decode JWT tokens to display their contents (same approach as regular tokens page)
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
		
		// Get raw tokens
		const id_token = req.oidc.idToken
		const access_token = req.oidc.accessToken
		const refresh_token = req.oidc.refreshToken

		res.render('tokens', {
			title: 'Partner Portal',
			user: req.oidc.user,
			id_token_payload: idTokenPayload,
			access_token_payload: accessTokenPayload,
			refresh_token,
			id_token,
			access_token,
			userTier: req.userTier || 'unknown'
		})
	} catch (error) {
		console.error('Error rendering partners tokens page:', error)
		res.status(500).render('error', {
			title: 'Partner Portal - Error',
			message: 'Error loading token details',
			error: error.message
		})
	}
})

// Partners-specific profile page
app.get('/partners/profile', requiresAuth(), async (req, res) => {
	try {
		// Define the URLs for the two APIs you want to call
		const token = await getManagementApiToken()
		const userId = req.oidc.user.sub;
		const authz_header = { Authorization: `Bearer ${token}` };
		
		const url1 = `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`;
		const url2 = `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}/authentication-methods`;

		console.log('Initiating API calls for partners profile...');

		// Use Promise.all to make concurrent requests
		const [response1, response2] = await Promise.all([
			axios.get(url1, { headers: authz_header }),
			axios.get(url2, { headers: authz_header })
		]);

		console.log('Both API calls completed successfully for partners profile!');

		// You can now access the data from each response
		const user = response1.data;
		const factors = response2.data;
		const userTier = req.userTier || 'unknown'
		const userPermissions = req.userPermissions || []

		// Check for profile update success message
		const updated = req.query.updated === 'true'

		const clientId = `${process.env.CLIENT_ID}`;
		const mgmtUrl = `${process.env.MGMT_BASE_URL}`;
		const issuerUrl = `${process.env.ISSUER_BASE_URL}`;
		const appUrl = `${process.env.APP_URL}`;

		res.render('profile2', {
			title: 'Partner Portal',
			user,
			factors,
			userTier,
			userPermissions,
			updated,
			clientId,
			issuerUrl,
			mgmtUrl,
			appUrl,
			updateSuccess: updated
		})
	} catch (error) {
		console.error('Error rendering partners profile page:', error)
		res.status(500).render('error', {
			title: 'Partner Portal - Error',
			message: 'Error loading profile',
			error: error.message
		})
	}
})

// Partners dashboard for org admins
app.get('/partners/dashboard', requiresAuth(), async (req, res) => {
	try {
		const user = req.oidc.user
		const userTier = req.userTier || 'unknown'
		
		// Extract organization information from the user's ID token
		const orgId = req.oidc.idTokenClaims?.org_id
		const orgName = req.oidc.idTokenClaims?.org_name
		
		console.log('Dashboard - User org info:', { orgId, orgName, userId: user.sub })
		console.log('Dashboard - User access token claims:', req.oidc.accessTokenClaims)
		console.log('Dashboard - User ID token claims:', req.oidc.idTokenClaims)
		console.log('Dashboard - User tier from middleware:', req.userTier)
		
		if (!orgId) {
			return res.status(400).render('error', {
				title: 'Partner Portal - Error',
				message: 'No organization found in your account. Please contact support.',
				error: 'Organization not found'
			})
		}
		
		// Get organization details and members
		const token = await getManagementApiToken()
		const authz_header = { Authorization: `Bearer ${token}` }
		
		// Fetch organization details, members, and invitations
		const [orgResponse, membersResponse, invitationsResponse] = await Promise.all([
			axios.get(`${process.env.MGMT_BASE_URL}/api/v2/organizations/${orgId}`, { headers: authz_header }),
			axios.get(`${process.env.MGMT_BASE_URL}/api/v2/organizations/${orgId}/members`, { headers: authz_header }),
			axios.get(`${process.env.MGMT_BASE_URL}/api/v2/organizations/${orgId}/invitations`, { headers: authz_header })
		])
		
		const organization = orgResponse.data
		const allMembers = membersResponse.data
		const allInvitations = invitationsResponse.data
		
		// Filter to only show org users (hide other org admins)
		// If current user is org admin, they should only see org users
		// If current user is org user, they shouldn't see the dashboard at all (this should be handled by route protection)
		let members = allMembers
		let invitations = allInvitations
		
		// If current user is org admin, filter out other org admins
		if (req.userPermissions && req.userPermissions.includes('org:admin')) {
			console.log('Current user is org admin - filtering other org admins from view')
			
			// Since we can't easily get other users' access tokens to check their permissions,
			// we'll use a different approach: check the user metadata for the intended role
			// that was set during invitation
			const membersWithRoleInfo = await Promise.all(
				allMembers.map(async (member) => {
					try {
						const userResponse = await axios.get(
							`${process.env.MGMT_BASE_URL}/api/v2/users/${member.user_id}`, 
							{ headers: authz_header }
						)
						
						// Check app_metadata for the intended role from invitation
						const intendedRole = userResponse.data.app_metadata?.invitedRole
						const isOrgAdmin = intendedRole === 'org-admin' || intendedRole === 'org:admin'
						
						console.log(`User ${member.email} - intendedRole: ${intendedRole}, isOrgAdmin: ${isOrgAdmin}`)
						
						return {
							...member,
							intendedRole: intendedRole,
							isOrgAdmin: isOrgAdmin
						}
					} catch (error) {
						console.error(`Error fetching user data for ${member.user_id}:`, error.message)
						return {
							...member,
							intendedRole: null,
							isOrgAdmin: false // Default to showing them if we can't determine
						}
					}
				})
			)
			
			// Filter out other org admins (keep current user and org users)
			members = membersWithRoleInfo.filter(member => 
				member.user_id === user.sub || !member.isOrgAdmin
			)
			
			console.log(`Filtered members: ${members.length} (removed ${allMembers.length - members.length} org admins)`)
		}
		
		console.log('Dashboard - Organization data:', { 
			orgName: organization.display_name, 
			memberCount: members.length,
			invitationCount: invitations.length,
			membersStructure: members,
			invitationsStructure: invitations
		})
		
		// Debug: Log current user's permissions
		console.log('Dashboard - Current user permissions:', req.userPermissions)
		console.log('Dashboard - Current user tier:', req.userTier)
		
		res.render('partners-dashboard', {
			title: 'Partner Portal',
			user,
			userTier,
			userPermissions: req.userPermissions,
			organization,
			members,
			invitations,
			orgId,
			orgName: organization.display_name
		})
		
	} catch (error) {
		console.error('Error loading partners dashboard:', error)
		res.status(500).render('error', {
			title: 'Partner Portal - Error',
			message: 'Error loading dashboard',
			error: error.message
		})
	}
})

// Handle user invitation from dashboard
app.post('/partners/dashboard/invite', requiresAuth(), async (req, res) => {
	try {
		const { email, role } = req.body
		const user = req.oidc.user
		
		// Extract organization information from the user's ID token
		const orgId = req.oidc.idTokenClaims?.org_id
		const orgName = req.oidc.idTokenClaims?.org_name
		
		console.log('Invite user - Org info:', { orgId, orgName, email, role })
		
		if (!orgId) {
			return res.status(400).json({ 
				success: false, 
				error: 'No organization found in your account' 
			})
		}
		
		// Validate required fields
		if (!email) {
			return res.status(400).json({ 
				success: false, 
				error: 'Please provide an email address' 
			})
		}
		
		// Validate role IDs are configured
		if (!process.env.ORG_ADMIN_ROLE_ID || !process.env.ORG_USER_ROLE_ID) {
			console.error('Missing role IDs in environment variables:', {
				ORG_ADMIN_ROLE_ID: process.env.ORG_ADMIN_ROLE_ID ? 'SET' : 'MISSING',
				ORG_USER_ROLE_ID: process.env.ORG_USER_ROLE_ID ? 'SET' : 'MISSING'
			})
			return res.status(500).json({ 
				success: false, 
				error: 'Role configuration error. Please contact support.' 
			})
		}
		
		// Get Auth0 Management API token
		const token = await getManagementApiToken()
		const authz_header = { Authorization: `Bearer ${token}` }
		
		// Get organization details and enabled connections
		const [orgResponse, connectionsResponse] = await Promise.all([
			axios.get(`${process.env.MGMT_BASE_URL}/api/v2/organizations/${orgId}`, { headers: authz_header }),
			axios.get(`${process.env.MGMT_BASE_URL}/api/v2/organizations/${orgId}/enabled_connections`, { headers: authz_header })
		])
		
		const organization = orgResponse.data
		const enabledConnections = connectionsResponse.data
		console.log('Organization details:', organization)
		console.log('Enabled connections:', enabledConnections)
		
		// Use organization name from API response since orgName from token might be undefined
		const orgDisplayName = organization.display_name || organization.name || orgName || 'organization'
		
		// Find the organization's connection ID (should be the one we created during registration)
		const connectionName = `${orgDisplayName.toLowerCase().replace(/[^a-z0-9-]/g, '-')}-connection`
		const connection = enabledConnections.find(conn => conn.connection.name === connectionName)
		
		if (!connection) {
			console.error('Connection not found:', { connectionName, enabledConnections })
			return res.status(400).json({ 
				success: false, 
				error: 'Organization connection not found. Please contact support.' 
			})
		}
		
		const connectionId = connection.connection.id
		console.log('Using connection ID:', { connectionName, connectionId })
		
		// Determine which role ID to use
		const roleId = role === 'org-admin' ? process.env.ORG_ADMIN_ROLE_ID : process.env.ORG_USER_ROLE_ID
		console.log('Using role ID:', { role, roleId })
		
		// Create invitation data
		const invitationData = {
			inviter: {
				name: user.name || user.email
			},
			invitee: {
				email: String(email)
			},
			client_id: process.env.CLIENT_ID,
			connection_id: connectionId,
			app_metadata: {
				organizationId: String(orgId),
				organizationName: String(orgDisplayName),
				invitedBy: String(user.sub),
				invitedRole: String(role || 'org-user')
			},
			user_metadata: {
				invitedBy: String(user.name || user.email)
			},
			ttl_sec: 604800, // 7 days
			send_invitation_email: true,
			roles: [roleId] // Use role ID from environment variables
		}
		
		console.log('Sending organization invitation:', JSON.stringify(invitationData, null, 2))
		
		// Send the invitation
		const invitationResponse = await axios.post(
			`${process.env.MGMT_BASE_URL}/api/v2/organizations/${orgId}/invitations`,
			invitationData,
			{
				headers: { 
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json'
				}
			}
		)
		
		const invitationId = invitationResponse.data.id
		console.log('Successfully sent invitation with ID:', invitationId)
		
		res.json({ 
			success: true, 
			message: 'User invitation sent successfully!',
			invitationId: invitationId
		})
		
	} catch (error) {
		console.error('Error sending user invitation:', error)
		
		let errorMessage = 'An error occurred while sending the invitation. Please try again.'
		
		if (error.response) {
			console.error('Auth0 API Error Response:', {
				status: error.response.status,
				statusText: error.response.statusText,
				data: error.response.data
			})
			
			if (error.response.data) {
				errorMessage = error.response.data.message || error.response.data.error_description || errorMessage
			}
		}
		
		res.status(500).json({ 
			success: false, 
			error: errorMessage 
		})
	}
})

// Debug route to test different scopes for organization users
app.get('/partners/debug-scopes', (req, res) => {
	const testScopes = [
		'openid profile email',
		'openid profile email read:current_user',
		'openid profile email read:organizations',
		'openid profile email read:current_user read:organizations'
	];
	
	res.render('debug-scopes', {
		title: 'Partner Portal - Scope Debug',
		testScopes: testScopes,
		currentScope: process.env.SCOPE,
		currentAudience: process.env.AUDIENCE
	});
});

app.get('/force-refresh', requiresAuth(), (req, res) => {
  // Force a complete logout/login to refresh tokens
  res.oidc.logout({
    returnTo: '/profile'
  });
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
    } catch (fgaError) {
      console.error('Error updating FGA tier permissions during upgrade:', fgaError);
      // Don't fail the upgrade if FGA update fails, just log the error
    }
    
    // Store upgrade info in session for the success page
    req.session.upgradeInfo = {
      tier: tier,
      upgradedAt: new Date().toISOString()
    };
    
    // Force a complete logout/login to ensure fresh tokens with new permissions
    res.oidc.logout({
      returnTo: '/upgrade-success?upgraded=true&tier=' + tier
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
    
    const url1 = `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`;
    const url2 = `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}/authentication-methods`;

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
  
  // Check if this is a successful update redirect
  const updateSuccess = req.query.updated === 'true';
  
  res.render('profile2', 
	{ user: res.locals.user, 
	  factors: res.locals.factors, 
	  clientId, 
	  issuerUrl, 
	  mgmtUrl, 
	  appUrl,
	  updateSuccess: updateSuccess
	});
});


// Handle profile updates - Step 1: Store data and redirect to Auth0 for MFA
app.post('/profile', requiresAuth(), async (req, res) => {
  const { name, email, first_name, last_name, consents } = req.body;
  const sanitizedConsents = Array.isArray(consents) ? consents.filter(Boolean) : [];

  try {
    // Store pending profile update data in session
    req.session.pendingProfileUpdate = {
      name,
      email,
      first_name,
      last_name,
      consents: sanitizedConsents,
      timestamp: new Date().toISOString()
    };

    console.log('Stored pending profile update, redirecting to Auth0 for MFA verification');
    
    // Build Auth0 authorization URL with MFA requirement
    const auth0AuthUrl = new URL(`${process.env.ISSUER_BASE_URL}/authorize`);
    auth0AuthUrl.searchParams.set('response_type', 'code');
    auth0AuthUrl.searchParams.set('client_id', process.env.CLIENT_ID);
    auth0AuthUrl.searchParams.set('redirect_uri', `${process.env.APP_URL}/callback`);
    auth0AuthUrl.searchParams.set('scope', process.env.SCOPE);
    auth0AuthUrl.searchParams.set('audience', process.env.AUDIENCE);
    auth0AuthUrl.searchParams.set('state', 'profile-update-mfa');
    auth0AuthUrl.searchParams.set('prompt', 'mfa');
    auth0AuthUrl.searchParams.set('acr_values', 'http://schemas.openid.net/pape/policies/2007/06/multi-factor/challenge');
    
    // Store the return URL in session for after MFA completion
    req.session.mfaReturnTo = '/profile-update-complete';
    
    console.log('Redirecting to Auth0 with MFA requirement:', auth0AuthUrl.toString());
    res.redirect(auth0AuthUrl.toString());
    
  } catch (error) {
    console.error('Error initiating profile update with MFA:', error.message);
    res.status(500).send('Error initiating profile update.');
  }
});

// Handle profile update completion after MFA verification
app.get('/profile-update-complete', requiresAuth(), async (req, res) => {
  try {
    // Check if there's pending profile update data
    if (!req.session.pendingProfileUpdate) {
      console.log('No pending profile update found, redirecting to profile');
      return res.redirect('/profile');
    }

    const pendingUpdate = req.session.pendingProfileUpdate;
    const userId = req.oidc.user.sub;
    const token = await getManagementApiToken();

    console.log('Processing pending profile update after MFA verification');

    // Fetch current user data
    const userResponse = await axios.get(`${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    
    const currentMetadata = userResponse.data.user_metadata || {};
    
    // Merge existing metadata with new updates
    const updatedMetadata = {
      ...currentMetadata,
      consents: pendingUpdate.consents || "",
      first_name: pendingUpdate.first_name || "",
      last_name: pendingUpdate.last_name || ""
    };
    
    console.log('Updating user profile with verified session:', {
      user_metadata: updatedMetadata,
      email: pendingUpdate.email
    });
    
    // Update user metadata via Auth0 Management API
    await axios.patch(
      `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`,
      {
        user_metadata: updatedMetadata,
        email: pendingUpdate.email,
        name: pendingUpdate.name
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    // Clear pending update from session
    delete req.session.pendingProfileUpdate;
    
    console.log('Profile update completed successfully');
    
    // Redirect back to profile with success message
    res.redirect('/profile?updated=true');
    
  } catch (error) {
    console.error('Error completing profile update:', error.message);
    // Clear pending update on error
    delete req.session.pendingProfileUpdate;
    res.status(500).send('Error completing profile update.');
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

app.post('/toggle-mfa-optin', requiresAuth(), async (req, res) => {
  const userId = req.oidc.user.sub;
  const { optinmfa } = req.body;

  try {
    const token = await getManagementApiToken();

    // Update user metadata with MFA opt-in setting
    await axios.patch(
      `${process.env.MGMT_BASE_URL}/api/v2/users/${userId}`,
      {
        user_metadata: {
          optinmfa: optinmfa === 'true' ? 'true' : 'false'
        }
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    res.json({ 
      success: true, 
      message: `MFA opt-in ${optinmfa === 'true' ? 'enabled' : 'disabled'} successfully`,
      optinmfa: optinmfa === 'true' ? 'true' : 'false'
    });
  } catch (error) {
    console.error('Error updating MFA opt-in setting:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update MFA opt-in setting' 
    });
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
