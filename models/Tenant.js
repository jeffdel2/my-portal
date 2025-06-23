//var logger = require('../logger.js')
var logger = require('winston')

class Tenant {
    constructor(tenantProfileJson,sub) {
        if(tenantProfileJson){
            try {
                this.expires = new Date(new Date().getTime() + process.env.CACHE_DURATION*60000);
                logger.verbose("Expires: "+this.expires)
                console.log("inside tenant.js",this.expires);

                this.state = tenantProfileJson.state
                logger.verbose("State: "+this.state)

                this.issuer = tenantProfileJson.oidc_configuration.issuer
                logger.verbose("AuthzUrl: "+this.issuer)
                this.authorizationURL = tenantProfileJson.oidc_configuration.authorizeUrl,
                logger.verbose("AuthzUrl: "+this.authorizationURL)
                this.tokenURL= tenantProfileJson.oidc_configuration.tokenUrl,
                logger.verbose("TokenUrl: "+this.tokenURL)
                this.userInfoURL= tenantProfileJson.oidc_configuration.userInfoUrl,
                logger.verbose("UserInfoUrl: "+this.userInfoURL)
                this.clientID= tenantProfileJson.oidc_configuration.client_id
                logger.verbose("ClientID: "+this.clientID)
                this.clientSecret =  tenantProfileJson.oidc_configuration.client_secret
                if(this.clientSecret != null){
                    logger.verbose("ClientSecret: --present--")
                }
                else{
                    logger.warn("ClientSecret: --absent--")
                }
                var callback = new URL(process.env.BASE_URI)
                callback.hostname = `${sub}.${callback.hostname}`
                callback.pathname = '/callback'
                this.callbackURL = callback.toString()
                logger.verbose("CallbackURL: "+this.callbackURL)

                this.settings = tenantProfileJson.settings
            }
            catch(error) {
                logger.error(error);
            }
        }
        else {
            try {
                this.expires = null
                this.state = 'active'
                this.issuer = process.env.DEFAULT_ISSUER
                this.authorizationURL = process.env.DEFAULT_ISSUER+ '/v1/authorize'
                this.tokenURL = process.env.DEFAULT_ISSUER+'/v1/token',
                this.userInfoURL = process.env.DEFAULT_ISSUER+'/v1/userinfo',
                this.clientID = process.env.DEFAULT_CLIENT_ID,
                this.clientSecret = process.env.DEFAULT_CLIENT_SECRET,
                this.callbackURL = process.env.BASE_URI+'/callback'
            }
            catch(error) {
                logger.error(error);
            }
        }
    }

    isExpired(){
        logger.verbose("Checking if tenant data is expired.")
        if(this.expires === null){
            logger.verbose("Tenant data set to never expire.")
            return false
        }
        logger.verbose("Expiry timestamp "+this.expires)
        return new Date() > this.expires
    }
}

module.exports = Tenant