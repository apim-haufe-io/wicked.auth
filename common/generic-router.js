'use strict';

const async = require('async');
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:utils');
const wicked = require('wicked-sdk');
const oauth2 = require('../kong-oauth2/oauth2');
const tokens = require('../kong-oauth2/tokens');
const Router = require('express').Router;
const qs = require('querystring');

const utils = require('./utils');
const utilsOAuth2 = require('./utils-oauth2');
const { failMessage, failError, failOAuth, makeError } = require('./utils-fail');
const profileStore = require('./profile-store');

function GenericOAuth2Router(basePath, authMethodId/*, csrfProtection*/) {

    const oauthRouter = new Router();
    const state = {};
    const instance = this;

    this.getRouter = () => {
        return oauthRouter;
    };

    this.initIdP = (idp) => {
        state.idp = idp;
        // Configure additional end points (if applicable). JavaScript is sick.
        const endpoints = idp.endpoints();
        for (let i = 0; i < endpoints.length; ++i) {
            const e = endpoints[i];
            if (!e.uri)
                throw new Error('initIdP: Invalid end point definition, "uri" is null): ' + JSON.stringify(e));
            if (!e.handler)
                throw new Error('initIdP: Invalid end point definition, "handler" is null): ' + JSON.stringify(e));
            oauthRouter[e.method](e.uri, e.handler);
        }
    };

    // OAuth2 end point Authorize
    oauthRouter.get('/api/:apiId/authorize', /*csrfProtection,*/ function (req, res, next) {
        const apiId = req.params.apiId;
        debug(`/api/${apiId}/authorize`);

        const clientId = req.query.client_id;
        const responseType = req.query.response_type;
        const givenRedirectUri = req.query.redirect_uri;
        const givenState = req.query.state;
        const givenScope = req.query.scope;
        const givenPrompt = req.query.prompt;

        if (!req.session)
            req.session = {};
        if (!req.session[authMethodId])
            req.session[authMethodId] = { authRequest: {} };
        else if (!req.session[authMethodId].authRequest)
            req.session[authMethodId].authRequest = {};
        const authRequest = req.session[authMethodId].authRequest;
        authRequest.api_id = apiId;
        authRequest.client_id = clientId;
        authRequest.response_type = responseType;
        authRequest.redirect_uri = givenRedirectUri;
        authRequest.state = givenState;
        authRequest.scope = givenScope;
        authRequest.prompt = givenPrompt;

        // Validate parameters first now (TODO: This is pbly feasible centrally,
        // it will be the same for all Auth Methods).
        utilsOAuth2.validateAuthorizeRequest(authRequest, function (err, validationResult) {
            if (err) {
                return next(err);
            }

            // Is it a trusted application?
            authRequest.trusted = validationResult.trusted;

            utilsOAuth2.validateApiScopes(
                authRequest.api_id,
                authRequest.scope,
                authRequest.trusted,
                function (err, scopeValidationResult) {
                    if (err)
                        return next(err);

                    // Rewrite the scope to an array which resulted from the validation.
                    // Note that this is not the granted scopes, but the scopes that this
                    // application requests, and we have (only) validated that the scopes
                    // are present. If the application is not trusted, it may be that we
                    // will ask the user to grant the scope rights to the application later
                    // on.
                    authRequest.scope = scopeValidationResult.validatedScopes;
                    // Did we add/change the scopes passed in?
                    authRequest.scopesDiffer = scopeValidationResult.scopesDiffer;

                    let existingAuthResponse = req.session[authMethodId].authResponse;
                    // Borrowed from OpenID Connect, check for prompt request for implicit grant
                    // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
                    if (authRequest.response_type === 'token') {
                        switch (authRequest.prompt) {
                            case 'none':
                                if (!existingAuthResponse)
                                    return failOAuth(401, 'login_required', 'user must be logged in interactively, cannot authorize without logged in user.', next);
                                return authorizeFlow(req, res, next);
                            case 'login':
                                // Force login; wipe session data
                                if (existingAuthResponse) {
                                    delete req.session[authMethodId].authResponse;
                                    existingAuthResponse = null;
                                }
                                break;
                        }
                    }
                    // We're fine. Check for pre-existing sessions.
                    if (existingAuthResponse) {
                        return instance.continueAuthorizeFlow(req, res, next, existingAuthResponse);
                    }

                    // Not logged in, or forced login
                    // return local.renderLogin(req, res, apiId);
                    return state.idp.authorizeWithUi(req, res, authRequest);
                });
        });
    });

    /**
     * Checks for a user by custom ID.
     * 
     * @param {*} customId custom ID to check a user for; if there is a user
     * with this custom ID in the wicked database, the user will already have
     * an email address, and thus the IdP would not have to ask for one, in
     * case it doesn't provide one (e.g. Twitter).
     * @param {*} callback Returns (err, shortUserInfo), shortUserInfo may be
     * null in case the user doesn't exist, otherwise { id, customId, name, email }
     */
    this.existsUserWithCustomId = existsUserWithCustomId;
    function existsUserWithCustomId(customId, callback) {
        debug(`existsUserWithCustomId(${customId})`);
        wicked.apiGet(`/users?customId=${qs.escape(customId)}`, (err, shortInfoList) => {
            if (err && err.statusCode == 404) {
                // Not found
                return callback(null, null);
            } else if (err) {
                // Unexpected error
                return callback(err);
            }

            // Now we should have the user ID here:
            if (!Array.isArray(shortInfoList) || shortInfoList.length <= 0 || !shortInfoList[0].id)
                return callback(new Error('existsUserWithCustomId: Get user short info by email did not return a user id'));
            return callback(null, shortInfoList[0]);
        });
    }

    this.continueAuthorizeFlow = (req, res, next, authResponse) => {
        debug('continueAuthorizeFlow()');
        // TODO:
        // 1. Check if user already exists if only customId is filled
        // 2. (If not) Possibly create user in local database  
        //     --> Note that if the local IdP does not want this, it
        //         must not call continueAuthorizeFlow before the user
        //         has actually been created (via a signup form).
        // 3. Check registration status
        // 4. If not registered, and registration is needed, display 
        //    registration form (for the API's registration pool)
        // 5. (Email validation doohickey)

        // 6. Call authorizeFlow

        // Extra TODO:
        // - Pass-through APIs do not create local users
        checkUserFromAuthResponse(authResponse, (err, authResponse) => {
            if (err)
                return failMessage(500, 'checkUserFromAuthResponse: ' + err.message, next);

            if (!req.session[authMethodId].authRequest ||
                !req.session[authMethodId].authRequest.api_id)
                return failMessage(500, 'Invalid state: API in authorization request is missing.', next);

            const apiId = req.session[authMethodId].authRequest.api_id;
            req.session[authMethodId].authResponse = authResponse;

            debug('Retrieving registration info...');
            // We have an identity now, do we need registrations?
            utils.getApiRegistrationPool(apiId, (err, poolId) => {
                if (err)
                    return failError(500, err, next);

                debug(authResponse);

                if (!poolId) {
                    if (authResponse.registrationPool)
                        delete authResponse.registrationPool;
                    // Nope, just go ahead; use the default Profile as profile
                    authResponse.profile = utils.clone(authResponse.defaultProfile);
                    return authorizeFlow(req, res, next);
                }

                authResponse.registrationPool = poolId;
                debug(`API requires registration with pool '${poolId}', starting registration flow`);

                // We'll do the registrationFlow first then...
                return registrationFlow(poolId, req, res, next);
            });
        });
    };

    // !!!
    oauthRouter.post('/api/:apiId/token', function (req, res, next) {
        const apiId = req.params.apiId;
        debug(`/api/${apiId}/token`);
        // Full switch/case on things to do, for all flows
        // - Client Credentials -> Go to Kong and get a token
        // - Authorization Code -> Go to Kong and get a token
        // - Resource Owner Password Grant --> Check username/password/client id/secret and get a token
        // - Refresh Token --> Check validity of user and client --> Get a token

        const tokenRequest = utilsOAuth2.makeTokenRequest(req, apiId, authMethodId);
        utilsOAuth2.validateTokenRequest(tokenRequest, function (err, validationResult) {
            if (err)
                return next(err);
            // Ok, we know we have something which could work (all data)
            const handleTokenResult = function (err, accessToken) {
                if (err)
                    return failError(400, err, next);
                if (accessToken.error)
                    return res.status(400).json(accessToken);
                if (accessToken.session_data) {
                    profileStore.registerTokenOrCode(accessToken, tokenRequest.api_id, accessToken.session_data, (err) => {
                        if (err)
                            return failError(500, err, next);
                        delete accessToken.session_data;
                        return res.status(200).json(accessToken);
                    });
                } else {
                    return res.status(200).json(accessToken);
                }
            };

            switch (tokenRequest.grant_type) {
                case 'client_credentials':
                    // This is generically available for most auth methods
                    return utilsOAuth2.tokenClientCredentials(tokenRequest, handleTokenResult);
                case 'authorization_code':
                    // Use the generic version here as well
                    return utilsOAuth2.tokenAuthorizationCode(tokenRequest, handleTokenResult);
                case 'password':
                    // This has to be done specifically
                    return tokenPasswordGrant(tokenRequest, handleTokenResult);
                case 'refresh_token':
                    // This as well
                    return tokenRefreshToken(tokenRequest, handleTokenResult);
            }
            // This should not be possible
            return failOAuth(400, 'unsupported_grant_type', `invalid grant type ${tokenRequest.grant_type}`);
        });
    });

    oauthRouter.post('/register', (req, res, next) => {
        // ...
        debug(`/register`);

        // First, check the registration nonce
        const sessionData = req.session[authMethodId];
        const nonce = req.body.nonce;
        if (!nonce)
            return failMessage(400, 'Registration nonce missing.', next);
        if (nonce !== sessionData.registrationNonce)
            return failMessage(400, 'Registration nonce mismatch.', next);

        // OK, this looks fine.
        const userId = sessionData.authResponse.userId;
        const poolId = sessionData.authResponse.registrationPool;

        // The backend validates the data
        wicked.apiPut(`/registrations/pools/${poolId}/users/${userId}`, req.body, (err) => {
            if (err)
                return failError(500, err, next);
            
            // Go back to the registration flow now
            return registrationFlow(poolId, req, res, next);
        });
    });

    // =============================================
    // Helper methods
    // =============================================

    function registrationFlow(poolId, req, res, next) {
        debug('registrationFlow()');

        const authResponse = req.session[authMethodId].authResponse;
        const userId = authResponse.userId;
        wicked.apiGet(`/registrations/pools/${poolId}/users/${userId}`, (err, regInfo) => {
            if (err && err.statusCode !== 404)
                return failError(500, err, next);

            if (!regInfo) {
                // User does not have a registration here, we need to get one
                return renderRegister(req, res, next);
            } else {
                // User already has a registration, create a suitable profile
                // TODO: Here we could check for not filled required fields
                utilsOAuth2.makeOidcProfile(poolId, authResponse, regInfo, (err, profile) => {
                    if (err)
                        return utils.failError(500, err, next);
                    authResponse.profile = profile;
                    return authorizeFlow(req, res, next);
                });
            }
        });
    }

    function makeViewModel(req, defaultProfile) {
        return {
            title: req.app.glob.title,
            portalUrl: wicked.getExternalPortalUrl(),
            baseUrl: req.app.get('base_path'),
            // csrfToken: req.csrfToken(),
            loginUrl: `${authMethodId}/login`,
            logoutUrl: `logout`,
            signupUrl: `${authMethodId}/signup`,
            registerUrl: `${authMethodId}/register`,
            forgotPasswordUrl: `${authMethodId}/forgotpassword`
        };
    }

    function renderRegister(req, res, next) {
        debug('renderRegister()');
        // The profile is not yet available, doh
        //const userProfile = req.session[authMethodId].authResponse.profile;
        const authResponse = req.session[authMethodId].authResponse;
        const apiId = req.session[authMethodId].authRequest.api_id;
        debug(`API: ${apiId}`);

        utils.getPoolInfoByApi(apiId, (err, poolInfo) => {
            if (err)
                return failMessage(500, 'Invalid state, could not read API information for API ${apiId} to register for.', next);
            debug('Default profile:');
            debug(authResponse.defaultProfile);

            const viewModel = makeViewModel(req);
            viewModel.userId = authResponse.userId;
            viewModel.customId = authResponse.customId;
            viewModel.defaultProfile = authResponse.defaultProfile;
            viewModel.poolInfo = poolInfo;
            const nonce = utils.createRandomId();
            req.session[authMethodId].registrationNonce = nonce;
            viewModel.nonce = nonce;

            debug(viewModel);
            res.render('register', viewModel);
        });
    }

    function authorizeFlow(req, res, next) {
        debug('authorizeFlow()');
        const authRequest = req.session[authMethodId].authRequest;
        const userProfile = req.session[authMethodId].authResponse.profile;

        debug('/authorize/login: Calling authorization end point.');
        oauth2.authorize({
            response_type: authRequest.response_type,
            authenticated_userid: userProfile.sub,
            api_id: authRequest.api_id,
            client_id: authRequest.client_id,
            auth_method: req.app.get('server_name') + ':' + authMethodId,
            scope: authRequest.scope
        }, function (err, redirectUri) {
            debug('/authorize/login: Authorization end point returned.');
            if (err)
                return failError(400, err, next);
            if (!redirectUri.redirect_uri)
                return failMessage(500, 'Server error, no redirect URI returned.', next);
            let uri = redirectUri.redirect_uri;
            // For this redirect_uri, which can contain either a code or an access token,
            // associate the profile (userInfo).
            profileStore.registerTokenOrCode(redirectUri, authRequest.api_id, userProfile, (err) => {
                if (err)
                    return failError(500, err, next);
                if (authRequest.state)
                    uri += '&state=' + qs.escape(authRequest.state);
                return res.redirect(uri);
            });
        });
    }

    function tokenPasswordGrant(tokenRequest, callback) {
        debug('tokenPasswordGrant()');
        // Let's validate the subscription first...
        utilsOAuth2.validateSubscription(tokenRequest.client_id, tokenRequest.api_id, function (err, validationResult) {
            if (err)
                return callback(err);
            const trustedSubscription = validationResult.trusted;
            // Now we know whether we have a trusted subscription or not; only allow trusted subscriptions to
            // retrieve a token via the password grant.
            if (!trustedSubscription)
                return failOAuth(400, 'invalid_request', 'only trusted application subscriptions can retrieve tokens via the password grants.', callback);
            utilsOAuth2.validateApiScopes(tokenRequest.api_id, tokenRequest.scope, trustedSubscription, function (err, validatedScopes) {
                if (err)
                    return failOAuth(500, 'server_error', 'could not validate requested token scope', err, callback);
                // Update the scopes
                tokenRequest.scope = validatedScopes.validatedScopes;

                state.idp.authorizeByUserPass(tokenRequest.username, tokenRequest.password, (err, authResponse) => {
                    if (err) {
                        // Don't answer wrong logins immediately please.
                        // TODO: The error message must be IdP specific, can be some other type
                        // of error than just wrong username or password.
                        return setTimeout(() => {
                            return failOAuth(err.statusCode, 'invalid_request', 'invalid username or password', callback);
                        }, 500);
                    }

                    // TODO: In the LDAP case, the ROPG may work even if the user has not logged
                    // in and thus does not yet have a user in the wicked database; this user has to
                    // be created on the fly here, and possibly also needs a registration done
                    // automatically, if the API needs a registration. If not, it's fine as is, but
                    // the user needs a dedicated wicked local user (with a "sub" == user id)
                    checkUserFromAuthResponse(authResponse, (err, authResponse) => {
                        if (err) {
                            // TODO: Rethink error messages and such.
                            return setTimeout(() => {
                                return failOAuth(err.statusCode, 'invalid_request', 'could not unify auth response', callback);
                            }, 500);
                        }

                        // TODO: Check registration status - This can only work for APIs which need
                        // a registration if the user already *is* registered. OR: See above, in certain
                        // LDAP cases (configurable?) all registration data may already be taken from the
                        // default profile, and we're fine. This has to be checked what is (legally) allowed
                        // and what is (technically) possible.

                        // This was fine. Now check if we can issue a token.
                        tokenRequest.authenticated_userid = authResponse.userId;
                        tokenRequest.session_data = authResponse.profile;
                        oauth2.token(tokenRequest, callback);
                    });
                });
            });
        });
    }

    function checkUserFromAuthResponse(authResponse, callback) {
        // The Auth response contains the default profile, which may or may not
        // match the stored profile in the wicked database. Plus that we might need to
        // create a federated user record in case we have a good valid 3rd party user,
        // which we want to track in the user database of wicked.
        function loadUserAndProfile(userId) {
            debug(`loadUserAndProfile(${userId})`);
            wicked.apiGet(`/users/${userId}`, (err, userInfo) => {
                if (err)
                    return callback(err);
                debug('loadUserAndProfile returned.');

                // TODO: This is not good, and will not work like this
                // ATTENTION: This ought just fill userId and customId.
                // The rest is done when handling the registrations (see
                // registrationFlow()).
                const oidcProfile = utilsOAuth2.wickedUserInfoToOidcProfileSync(userInfo);
                authResponse.profile = oidcProfile;

                return callback(null, authResponse);
                // utilsOAuth2.wickedUserInfoToOidcProfile(userInfo, (err, oidcProfile) => {
                //     if (err)
                //         return callback(err);
                //     authResponse.profile = oidcProfile;
                //     return callback(null, authResponse);
                // });
            });
        }

        if (authResponse.userId) {
            // We already have a wicked user id, load the user and fill the profile
            return loadUserAndProfile(authResponse.userId);
        } else if (authResponse.customId) {
            // Let's check the custom ID, load by custom ID
            existsUserWithCustomId(authResponse.customId, (err, shortInfo) => {
                if (err)
                    return callback(err);
                if (!shortInfo) {
                    // Not found, we must create first
                    createUserFromDefaultProfile(authResponse, (err, authResponse) => {
                        if (err)
                            return callback(err);
                        return loadUserAndProfile(authResponse.userId);
                    });
                } else {
                    return loadUserAndProfile(shortInfo.id);
                }
            });
        } else {
            return callback(new Error('unifyAuthResponse: Neither customId nor userId was passed into authResponse.'));
        }
    }

    // Takes an authResponse, returns an authResponse
    function createUserFromDefaultProfile(authResponse, callback) {
        debug('createUserFromDefaultProfile()');
        // The defaultProfile MUST contain an email address.
        // The id of the new user is created by the API and returned here;
        // This is still an incognito user, name and such are amended later
        // in the process, via the registration.
        const userCreateInfo = {
            customId:  authResponse.customId,
            email:     authResponse.defaultProfile.email,
            validated: authResponse.defaultProfile.email_verified
        };
        wicked.apiPost('/users', userCreateInfo, (err, userInfo) => {
            if (err) {
                error('createUserFromDefaultProfile: POST to /users failed.');
                error(err);
                return callback(err);
            }
            debug(`createUserFromDefaultProfile: Created new user with id ${userInfo.id}`);
            // Hmmmmmm
            utilsOAuth2.wickedUserInfoToOidcProfile(userInfo, (err, oidcProfile) => {
                if (err)
                    return callback(err);
                authResponse.userId = userInfo.id;
                //authResponse.profile = oidcProfile;
                return callback(null, authResponse);
            });
        });
    }

    function tokenRefreshToken(tokenRequest, callback) {
        debug('tokenRefreshToken()');
        // Client validation and all that stuff can be done in the OAuth2 adapter,
        // but we still need to verify that the user for which the refresh token was
        // created is still a valid user.

        // TODO: For pass-through APIs, this cannot be used.
        const refreshToken = tokenRequest.refresh_token;
        tokens.getTokenDataByRefreshToken(refreshToken, function (err, tokenInfo) {
            if (err)
                return failOAuth(400, 'invalid_request', 'could not retrieve information on the given refresh token.', err, callback);
            debug('refresh token info:');
            debug(tokenInfo);
            const userId = tokenInfo.authenticated_userid;
            if (!userId)
                return failOAuth(500, 'server_error', 'could not correctly retrieve authenticated user id from refresh token', callback);
            state.idp.checkRefreshToken(tokenInfo, (err, refreshCheckResult) => {
                if (err)
                    return failOAuth(500, 'server_error', 'checking the refresh token returned an unexpected error.', callback);
                wicked.apiGet('users/' + userId, function (err, userInfo) {
                    if (err)
                        return failOAuth(400, 'invalid_request', 'user associated with refresh token is not a valid user (anymore)', err, callback);
                    debug('wicked local user info:');
                    debug(userInfo);
                    utilsOAuth2.wickedUserInfoToOidcProfile(userInfo, function (err, oidcProfile) {
                        if (err)
                            return failOAuth(500, 'server_error', 'could not convert wicked profile to OIDC profile', err, callback);
                        tokenRequest.session_data = oidcProfile;
                        // Now delegate to oauth2 adapter:
                        oauth2.token(tokenRequest, callback);
                    });
                });
            });
        });
    }
}

module.exports = GenericOAuth2Router;
