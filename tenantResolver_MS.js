/*
 * Copyright (c) 2021-Present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

/*
 * this code is called when the applciation initializes, it is responsible for grabbing the tenant in demo.okta that it is attached to.
 */
//packages
const axios = require('axios');

//models and constants
const Tenant = require('./models/Tenant');
const defaultTenantSub = "default";
const baseHost = new URL(process.env.BASE_URI).hostname;

let tenantStrategy = {};

//envs
const demoApiEndpoint =
  process.env.DEMO_API_ENDPOINT || "https://api.demo.okta.com";
//const REDIRECT_URI = `${window.location.origin}/login/callback`;
const OKTA_TESTING_DISABLEHTTPSCHECK =
  process.env.OKTA_TESTING_DISABLEHTTPSCHECK || false;

/**
 * clip the domain name from something like lavender-rattlesnake-43985.localhost:3000 to lavender-rattlesnake-43985
 * @param {*} domainName in the formation of example.org:8888
 * @returns
 */
const getTenant = (domainName) => {
  //for query params
  //let queryParams = new URLSearchParams(window.location.search);
  //let tenant = queryParams.get("demoName");

  //for subdomain
  let tenant = domainName.substr(0, domainName.indexOf("." + baseHost));
  console.log("TRYING CODE FOR TENANT", tenant);
  return tenant === "" ? "default" : tenant;
};
/**
 * creates config for the app
 * @param {*} tenant
 * @returns
 */
const configureTenantStrategy = (tenant) => {
  return {
    oidc: {
      clientId: tenant.clientID,
      issuer: tenant.issuer,
      authorizationURL: tenant.authorizationURL,
      tokenURL: tenant.tokenURL,
      userInfoURL: tenant.userInfoURL,
      clientSecret: tenant.clientSecret,
      callbackURL: tenant.callbackURL,
      scope: process.env.SCOPES,
      //redirectUri: REDIRECT_URI,
      //scopes: ["openid", "profile", "email", "clearance"],
      //scopes: ["openid", "profile", "email"],
      //pkce: true,
      disableHttpsCheck: OKTA_TESTING_DISABLEHTTPSCHECK,
    },
  };
};

const setupTenantsMap = () => {
  let tenants = new Map([]);

  if (
    process.env.DEFAULT_ISSUER &&
    process.env.DEFAULT_CLIENT_ID &&
    process.env.DEFAULT_CLIENT_SECRET
  ) {
    console.log(
      "Default config found this will be used for " + process.env.BASE_URI
    );
    tenants.set(defaultTenantSub, new Tenant(null, defaultTenantSub));
    tenantStrategy = configureTenantStrategy(tenants.get(defaultTenantSub));
  }
  if (
    !process.env.DEMO_API_APP_ID ||
    !process.env.DEMO_API_CLIENT_ID ||
    !process.env.DEMO_API_CLIENT_SECRET
  ) {
    console.log(
      "Missing environment variables for Demo API, configuration cannot be dynamically retrieved."
    );
  }
  return tenants;
};

async function resolveTenant(updateDemoName,
    updateOktaClientId,
    updateOktaIssuer) {
    let tenants = await setupTenantsMap();
    let clippedDomain = getTenant(window.location.host);
    if (clippedDomain == "") {
        clippedDomain = defaultTenantSub;
    }

    let tenant = tenants.get(clippedDomain);
    updateDemoName(clippedDomain);

    if (tenant == null || tenant.isExpired()) {
        try {
            var response = await axios.get(
                demoApiEndpoint +
                "/bootstrap/" +
                process.env.DEMO_API_APP_ID +
                "/" +
                clippedDomain
            );
            console.log("response = ", response);

            tenants.set(clippedDomain, new Tenant(response.data, clippedDomain));
            tenant = tenants.get(clippedDomain);
            console.log("tenant = ", tenant);
            updateOktaClientId(tenant.clientID);
            updateOktaIssuer(tenant.issuer);
            tenantStrategy = configureTenantStrategy(tenant, clippedDomain);
        } catch (error) {
            console.info(error);
            if (error.response && error.response.status == 404) {
                console.log("Unable to bootstrap demo " + clippedDomain);
            }
            // return res.redirect("/error");
        }
    }

    return tenantStrategy;
}