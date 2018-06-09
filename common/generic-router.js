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

const ERROR_TIMEOUT = 500; // ms

function GenericOAuth2Router(basePath, authMethodId) {

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
        const standardEndpoints = [
            {
                method: 'get',
                uri: '/verify/:verificationId',
                handler: instance.createVerifyHandler(authMethodId)
            },
            {
                method: 'post',
                uri: '/verify',
                handler: instance.createVerifyPostHandler(authMethodId)
            },
            {
                method: 'get',
                uri: '/verifyemail',
                handler: instance.createVerifyEmailHandler(authMethodId)
            },
            {
                method: 'post',
                uri: '/verifyemail',
                handler: instance.createVerifyEmailPostHandler(authMethodId)
            },
        ];
        // Spread operator, fwiw.
        endpoints.push(...standardEndpoints);
        for (let i = 0; i < endpoints.length; ++i) {
            const e = endpoints[i];
            if (!e.uri)
                throw new Error('initIdP: Invalid end point definition, "uri" is null): ' + JSON.stringify(e));
            if (!e.handler)
                throw new Error('initIdP: Invalid end point definition, "handler" is null): ' + JSON.stringify(e));
            if (e.middleware)
                oauthRouter[e.method](e.uri, e.middleware, e.handler);
            else
                oauthRouter[e.method](e.uri, e.handler);
        }
    };

    this.createVerifyHandler = (authMethodId) => {
        debug(`createVerifyEmailHandler(${authMethodId})`);
        // GET /verify/:verificationId
        return (req, res, next) => {
            debug(`verifyEmailHandler(${authMethodId})`);
            const verificationId = req.params.verificationId;
    
            wicked.apiGet(`/verifications/${verificationId}`, (err, verificationInfo) => {
                if (err && (err.statusCode === 404 || err.status === 404))
                    return setTimeout(failMessage, ERROR_TIMEOUT, 404, 'The given verification ID is not valid.', next);
                if (err)
                    return failError(500, err, next);
                if (!verificationInfo)
                    return setTimeout(failMessage, ERROR_TIMEOUT, 404, 'The given verification ID is not valid.', next);
    
                const viewModel = utils.createViewModel(req, authMethodId);
                viewModel.email = verificationInfo.email;
                viewModel.id = verificationId;
    
                switch (verificationInfo.type) {
                    case "email":
                        return res.render('verify_email', viewModel);
    
                    case "lostpassword":
                        return res.render('verify_password_reset', viewModel);
    
                    default:
                        return failMessage(500, `Unknown verification type ${verificationInfo.type}`, next);
                }
            });
        };
    };
    
    this.createVerifyPostHandler = (authMethodId) => {
        debug(`createVerifyPostHandler(${authMethodId})`);
        return (req, res, next) => {
            debug(`verifyPostHandler(${authMethodId})`);
    
            const body = req.body;
            const expectedCsrfToken = utils.getAndDeleteCsrfToken(req);
            const csrfToken = body._csrf;
            const verificationId = body.verification_id;
            const verificationType = body.type;
    
            if (!csrfToken || expectedCsrfToken !== csrfToken)
                return setTimeout(failMessage, ERROR_TIMEOUT, 403, 'CSRF validation failed.', next);
    
            wicked.apiGet(`/verifications/${verificationId}`, (err, verificationInfo) => {
                if (err && (err.statusCode === 404 || err.status === 404))
                    return setTimeout(failMessage, ERROR_TIMEOUT, 404, 'The given verification ID is not valid.', next);
                if (err)
                    return failError(500, err, next);
                if (!verificationInfo)
                    return setTimeout(failMessage, ERROR_TIMEOUT, 404, 'The given verification ID is not valid.', next);
                debug(`Successfully retrieved verification info for user ${verificationInfo.userId} (${verificationInfo.email})`);
    
                if (verificationType !== verificationInfo.type)
                    return failMessage(500, 'Verification information found, does not match form data (type)', next);
                switch (verificationType) {
                    case "email":
                        // We're fine, we can verify the user's email address via the wicked API (as the machine user)
                        wicked.apiPatch(`/users/${verificationInfo.userId}`, { validated: true }, (err, userInfo) => {
                            if (err)
                                return setTimeout(failError, ERROR_TIMEOUT, 500, err, next);
                            info(`Successfully patched user, validated email for user ${verificationInfo.userId} (${verificationInfo.email})`);
    
                            // Pop off a deletion of the verification, but don't wait for it.
                            wicked.apiDelete(`/verifications/${verificationId}`, (err) => { if (err) error(err); });
    
                            // Success
                            const viewModel = utils.createViewModel(req, authMethodId);
                            return res.render('verify_email_post', viewModel);
                        });
                        break;
                    case "lostpassword":
                        const password = body.password;
                        const password2 = body.password2;
                        if (!password || !password2 || password !== password2 || password.length > 25 || password.length < 6)
                            return failMessage(400, 'Invalid passwords/passwords do not match.', next);
                        // OK, let's give this a try
                        wicked.apiPatch(`/users/${verificationInfo.userId}`, { password: password }, (err, userInfo) => {
                            if (err)
                                return setTimeout(failError, ERROR_TIMEOUT, 500, err, next);
    
                            info(`Successfully patched user, changed password for user ${verificationInfo.userId} (${verificationInfo.email})`);
    
                            // Pop off a deletion of the verification, but don't wait for it.
                            wicked.apiDelete(`/verifications/${verificationId}`, (err) => { if (err) error(err); });
    
                            // Success
                            const viewModel = utils.createViewModel(req, authMethodId);
                            return res.render('verify_password_reset_post', viewModel);
                        });
                        break;
    
                    default:
                        return setTimeout(failMessage, ERROR_TIMEOUT, 500, `Unknown verification type ${verificationType}`, next);
                }
            });
        };
    };
    
    this.createForgotPasswordHandler = (authMethodId) => {
        debug(`createForgotPasswordHandler(${authMethodId})`);
        return (req, res, next) => {
            debug(`forgotPasswordHandler(${authMethodId})`);
    
            const viewModel = utils.createViewModel(req, authMethodId);
            return res.render('forgot_password', viewModel);
        };
    };
        
    this.createForgotPasswordPostHandler = (authMethodId) => {
        debug(`createForgotPasswordPostHandler(${authMethodId})`);
        return (req, res, next) => {
            debug(`forgotPasswordPostHandler(${authMethodId})`);
    
            const body = req.body;
            const expectedCsrfToken = utils.getAndDeleteCsrfToken(req);
            const csrfToken = body._csrf;
            const email = body.email;
    
            if (!csrfToken || expectedCsrfToken !== csrfToken)
                return setTimeout(failMessage, ERROR_TIMEOUT, 403, 'CSRF validation failed.', next);
            let emailValid = /.+@.+/.test(email);
            if (emailValid) {
                // Try to retrieve the user from the database
                wicked.apiGet(`/users?email=${qs.escape(email)}`, (err, userInfoList) => {
                    if (err)
                        return error(err);
                    if (!Array.isArray(userInfoList))
                        return warn('forgotPasswordPostHandler: GET users by email did not return an array');
                    if (userInfoList.length !== 1)
                        return warn(`forgotPasswordPostHandler: GET users by email returned a list of length ${userInfoList.length}, expected length 1`);
                    // OK, we have exactly one user
                    const userInfo = userInfoList[0];
                    info(`Issuing password reset request for user ${userInfo.id} (${userInfo.email})`);
    
                    // Fire off the verification/password reset request creation (the mailer will take care
                    // of actually sending the emails).
                    const authUrl = utils.getExternalUrl();
                    const resetLink = `${authUrl}/${authMethodId}/verify/{{id}}`;
    
                    const verifInfo = {
                        type: 'lostpassword',
                        email: userInfo.email,
                        userId: userInfo.id,
                        link: resetLink
                    };
                    wicked.apiPost('/verifications', verifInfo, (err) => {
                        if (err)
                            return error(err);
                        debug(`SUCCESS: Issuing password reset request for user ${userInfo.id} (${userInfo.email})`);
                    });
                });
            }
    
            // No matter what happens, we will send the same page to the user.
            const viewModel = utils.createViewModel(req, authMethodId);
            res.render('forgot_password_post', viewModel);
        };
    };
    
    this.createVerifyEmailHandler = (authMethodId) => {
        debug(`createVerifyEmailHandler(${authMethodId})`);
        return (req, res, next) => {
            debug(`verifyEmailHandler(${authMethodId})`);
    
            // Steps:
            // 1. Verify that the user is logged in
            // 2. Display a small form
            // 3. Let user click a button and we will send an email (via portal-mailer)
    
            if (!utils.isLoggedIn(req, authMethodId)) {
                // User is not logged in; make sure we do that first
                const thisUri = req.originalUrl;
                const redirectUri = `${req.app.get('base_path')}/${authMethodId}/login?redirect_uri=${qs.escape(thisUri)}`;
                return res.redirect(redirectUri);
            }
            // const redirectUri = `${req.app.get('base_url')}${authMethodId}/verifyemail`;
    
            debug(`verifyEmailHandler(${authMethodId}): User is correctly logged in.`);
    
            const viewModel = utils.createViewModel(req, authMethodId);
            viewModel.profile = req.session[authMethodId].authResponse.profile;
    
            return res.render('verify_email_request', viewModel);
        };
    };
    
    this.createVerifyEmailPostHandler = (authMethodId) => {
        debug(`createVerifyEmailPostHandler(${authMethodId})`);
        return (req, res, next) => {
            debug(`verifyEmailPostHandler(${authMethodId})`);
    
            const body = req.body;
            const expectedCsrfToken = utils.getAndDeleteCsrfToken(req);
            const csrfToken = body._csrf;
    
            if (!utils.isLoggedIn(req, authMethodId))
                return failMessage(403, 'You must be logged in to request email validation.', next);
            if (!csrfToken || expectedCsrfToken !== csrfToken)
                return setTimeout(failMessage, ERROR_TIMEOUT, 403, 'CSRF validation failed.', next);
    
            const profile = utils.getProfile(req, authMethodId);
            const email = profile.email;
    
            // If we're here, the user is not trusted (as we're asking for a validation)
            const trustUsers = false;
            utils.createVerificationRequest(trustUsers, authMethodId, email, (err) => {
                if (err)
                    return failError(500, err, next);
                return res.render('verify_email_request_confirm', utils.createViewModel(req, authMethodId));
            });
        };
    };
    
    this.createEmailMissingHandler = (authMethodId, continueAuthenticate) => {
        debug(`createEmailMissingHandler(${authMethodId})`);
        return (req, res, next, customId) => {
            debug(`emailMissingHandler(${authMethodId})`);
    
            utils.getUserByCustomId(customId, (err, userInfo) => {
                if (err)
                    return failError(500, err, next);
                // Known user, and known email address?
                if (userInfo && userInfo.email)
                    return continueAuthenticate(req, res, next, userInfo.email);
                // Unknown user, ask for email please            
                const viewModel = utils.createViewModel(req, authMethodId);
                return res.render('email_missing', viewModel);
            });
        };
    };
    
    this.createEmailMissingPostHandler = (authMethodId, continueAuthenticate) => {
        debug(`createEmailMissingPostHandler(${authMethodId})`);
        return (req, res, next) => {
            debug(`emailMissingPostHandler(${authMethodId})`);
    
            const body = req.body;
            const expectedCsrfToken = utils.getAndDeleteCsrfToken(req);
            const csrfToken = body._csrf;
    
            if (!csrfToken || expectedCsrfToken !== csrfToken)
                return setTimeout(failMessage, ERROR_TIMEOUT, 403, 'CSRF validation failed.', next);
    
            const email = body.email;
            const email2 = body.email2;
    
            if (!email || !email2)
                return setTimeout(failMessage, ERROR_TIMEOUT, 400, 'Email address or confirmation not passed in.', next);
            if (email !== email2)
                return setTimeout(failMessage, ERROR_TIMEOUT, 400, 'Email address and confirmation of email address do not match', next);
    
            // Pass back email address to calling IdP (e.g. Twitter)
            return continueAuthenticate(req, res, next, email);
        };
    };
    
    const initAuthRequest = (req) => {
        debug(`initAuthRequest(${authMethodId})`);
        if (!req.session)
            req.session = {};
        if (!req.session[authMethodId])
            req.session[authMethodId] = { authRequest: {} };
        else // Reset the authRequest even if it's present
            req.session[authMethodId].authRequest = {};
        const authRequest = req.session[authMethodId].authRequest;
        return authRequest;
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

        const authRequest = initAuthRequest(req);
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
                (err, scopeValidationResult) => {
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

                    let isLoggedIn = utils.isLoggedIn(req, authMethodId);
                    // Borrowed from OpenID Connect, check for prompt request for implicit grant
                    // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
                    if (authRequest.response_type === 'token') {
                        switch (authRequest.prompt) {
                            case 'none':
                                if (!isLoggedIn)
                                    return failOAuth(401, 'login_required', 'user must be logged in interactively, cannot authorize without logged in user.', next);
                                return authorizeFlow(req, res, next);
                            case 'login':
                                // Force login; wipe session data
                                if (isLoggedIn) {
                                    delete req.session[authMethodId].authResponse;
                                    isLoggedIn = false;
                                }
                                break;
                        }
                    }
                    // We're fine. Check for pre-existing sessions.
                    if (isLoggedIn) {
                        const authResponse = req.session[authMethodId].authResponse;
                        return instance.continueAuthorizeFlow(req, res, next, authResponse);
                    }

                    // Not logged in, or forced login
                    return state.idp.authorizeWithUi(req, res, authRequest);
                });
        });
    });

    /**
     * End point for interactive login without using the OAuth2 mechanisms; this
     * is used in cases where we need a logged in user, but there is none; e.g.
     * scope management, or verifying email addresses.
     * 
     * This end point displays the provider specific login page, and requires
     * a redirect URL to get back to (which must be internal to this application).
     * In short: Use this when you need to make sure that you have a logged in user
     * and just need to redirect back to a page when it's done.
     * 
     * Parameters: Query parameter "redirect_uri", which takes a relative path
     * to this application (including the base_path).
     */
    oauthRouter.get('/login', (req, res, next) => {
        debug('GET /login - internal login');

        // Verify parameters
        const redirectUri = req.query.redirect_uri;
        if (!redirectUri)
            return failMessage(400, 'Missing redirect_uri query parameter.', next);

        // Are we already logged in?
        if (utils.isLoggedIn(req, authMethodId)) {
            // Yup, let's just redirect
            return res.redirect(redirectUri);
        }

        // We're not yet logged in; let's do that now

        // Remember we're in a "special mode", so let's create a special type
        // of authRequest. The authRequest goes into the session.
        const authRequest = initAuthRequest(req);
        authRequest.plain = true;
        authRequest.redirect_uri = redirectUri;

        return state.idp.authorizeWithUi(req, res, authRequest);
    });

    this.continueAuthorizeFlow = (req, res, next, authResponse) => {
        debug('continueAuthorizeFlow()');
        // This is what happens here:
        //
        // 1. Check if user already exists if only customId is filled
        // 2. (If not) Possibly create user in local database  
        //     --> Note that if the local IdP does not want this, it
        //         must not call continueAuthorizeFlow before the user
        //         has actually been created (via a signup form).
        // 3. Check registration status
        // 4. If not registered, and registration is needed, display 
        //    registration form (for the API's registration pool)
        // 5. Check granted scopes, if not a trusted application is calling
        // 6. Call authorizeFlow

        // Extra TODO:
        // - Pass-through APIs do not create local users
        checkUserFromAuthResponse(authResponse, (err, authResponse) => {
            if (err)
                return failMessage(500, 'checkUserFromAuthResponse: ' + err.message, next);

            const authRequest = req.session[authMethodId].authRequest;
            if (!authRequest)
                return failMessage(500, 'Invalid state: authRequest is missing.', next);

            // Check for plain login mode (where there is no API involved)
            if (authRequest.plain) {
                if (!authRequest.redirect_uri)
                    return failMessage(500, 'Invalid state: authRequest.redirect_uri is missing.', next);
                // In this case, we don't need to check for any registrations; this is actually
                // not possible here, as there is no API to check with. We'll just continue with
                // redirecting to the redirect_uri in the authRequest (see GET /login).
                req.session[authMethodId].authResponse = authResponse;

                debug(`continueAuthorizeFlow(${authMethodId}): Doing plain login/redirecting: ${authRequest.redirect_uri}`);
                return res.redirect(authRequest.redirect_uri);
            }

            // Regular mode, we have an API we want to check registration state for.
            if (!authRequest.api_id)
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
            return failOAuth(400, 'unsupported_grant_type', `invalid grant type ${tokenRequest.grant_type}`, next);
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
                    // This will override the default user profile which is already
                    // present, but that is fine.
                    authResponse.profile = profile;
                    return authorizeFlow(req, res, next);
                });
            }
        });
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

            const viewModel = utils.createViewModel(req, authMethodId);
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

    // This is called as soon as we are sure that we have a logged in user, and possibly
    // also a valid registration record (if applicable to the API). Now we also have to
    // check the scope of the authorization request, and possible run the scopeFlow.
    function authorizeFlow(req, res, next) {
        debug(`authorizeFlow(${authMethodId})`);
        const authRequest = req.session[authMethodId].authRequest;
        const userProfile = req.session[authMethodId].authResponse.profile;

        if (authRequest.trusted || authRequest.scope.length === 0) {
            // We have a trusted application, or an empty scope, we will not need to check for scope grants.
            return authorizeFlow_Step2(req, res, next);
        }

        return failMessage(500, 'Scope flow not yet implemented', next);
        // return scopeFlow(req, res, next);
    }

    // Here we validate the scope, check for whether the user has granted the scopes to the
    // application or not.
    function scopeFlow(req, res, next) {
        debug(`scopeFlow(${authMethodId}`);

        const authRequest = req.session[authMethodId].authRequest;
        const authResponse = req.session[authMethodId].authResponse;

        const apiId = authRequest.api_id;
        const clientId = authRequest.client_id;
        const userId = authResponse.userId;

        // Retrieve the application info for this client_id; the client_id is attached
        // to the subscription (glue between API, application and plan), but we get the
        // application back readily when asking for the subscription.
        wicked.apiGet(`/subscriptions/${clientId}`, (err, subsInfo) => {
            if (err)
                return failError(500, err, next);
            const appInfo = subsInfo.application;
            if (!appInfo)
                return failMessage(500, 'scopeFlow: Could not retrieve application info from client_id', next);

            // Let's check whether the user already has some grants
            wicked.apiGet(`/grants/${userId}/applications/${appInfo.id}/apis/${apiId}`, (err, grant) => {
                if (err && err.status !== 404)
                    return failError(500, err, next);
                if (err) // status 404
                    grant = null; // will already be null though
                
            });
        });
    }

    function authorizeFlow_Step2(req, res, next) {
        debug(`authorizeFlow_Step2(${authMethodId})`);
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
        function loadWickedUser(userId) {
            debug(`loadWickedUser(${userId})`);
            wicked.apiGet(`/users/${userId}`, (err, userInfo) => {
                if (err)
                    return callback(err);
                debug('loadUserAndProfile returned.');

                // This just fills userId.
                // The rest is done when handling the registrations (see
                // registrationFlow()).
                const oidcProfile = utilsOAuth2.wickedUserInfoToOidcProfileSync(userInfo);
                authResponse.userId = userId;
                authResponse.profile = oidcProfile;

                return callback(null, authResponse);
            });
        }

        if (authResponse.userId) {
            // We already have a wicked user id, load the user and fill the profile
            return loadWickedUser(authResponse.userId);
        } else if (authResponse.customId) {
            // Let's check the custom ID, load by custom ID
            utils.getUserByCustomId(authResponse.customId, (err, shortInfo) => {
                if (err)
                    return callback(err);
                if (!shortInfo) {
                    // Not found, we must create first
                    createUserFromDefaultProfile(authResponse, (err, authResponse) => {
                        if (err)
                            return callback(err);
                        return loadWickedUser(authResponse.userId);
                    });
                } else {
                    return loadWickedUser(shortInfo.id);
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
            customId: authResponse.customId,
            email: authResponse.defaultProfile.email,
            validated: authResponse.defaultProfile.email_verified
        };
        wicked.apiPost('/users', userCreateInfo, (err, userInfo) => {
            if (err) {
                error('createUserFromDefaultProfile: POST to /users failed.');
                error(err);
                return callback(err);
            }
            debug(`createUserFromDefaultProfile: Created new user with id ${userInfo.id}`);
            authResponse.userId = userInfo.id;

            // Check whether we need to create a verification request, in case the email
            // address is not yet verified by the federated IdP (can happen with Twitter).
            // That we do asynchronously and return immediately without waiting for that.
            if (!userCreateInfo.validated) {
                info(`Creating email verification request for email ${userCreateInfo.email}...`);
                utils.createVerificationRequest(false, authMethodId, userCreateInfo.email, (err) => {
                    if (err) {
                        error(`Creating email verification request for email ${userCreateInfo.email} failed`);
                        error(err);
                        return;
                    }
                    info(`Created email verification request for email ${userCreateInfo.email} successfully`);
                    return;
                });
            }

            return callback(null, authResponse);
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
