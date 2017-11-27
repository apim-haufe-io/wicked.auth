const debug = require('debug')('portal-auth:local');
const qs = require('querystring');
const wicked = require('wicked-sdk');
const { oauth2, tokens } = require('wicked-kong-oauth2');
const Router = require('express').Router;

const utils = require('./utils');
const { failMessage, failError, failOAuth, makeError } = require('./utils-fail');
const profileStore = require('./profile-store');

module.exports = function (basePath, authMethodId, csrfProtection) {
    const local = new Router();

    // Not actually necessary to keep those here.
    local.basePath = basePath;
    local.authMethodId = authMethodId;

    local.renderLogin = function (req, res, apiId, flashError) {
        res.render('login', {
            title: req.app.glob.title,
            portalUrl: wicked.getExternalPortalUrl(),
            baseUrl: req.app.get('base_path'),
            csrfToken: req.csrfToken(),
            errorMessage: flashError,
            loginUrl: `${authMethodId}/api/${apiId}/authorize/login`
        });
    };

    // Interface for this Auth Method
    local.get('/api/:apiId/authorize', csrfProtection, function (req, res, next) {
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
        utils.validateAuthorizeRequest(authRequest, function (err, validationResult) {
            if (err) {
                return next(err);
            }

            // Is it a trusted application?
            authRequest.trusted = validationResult.trusted;

            utils.validateApiScopes(
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

                    let isLoggedIn = req.session[authMethodId].userInfo;
                    // Borrowed from OpenID Connect, check for prompt request for implicit grant
                    // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
                    if (authRequest.response_type === 'token') {
                        switch (authRequest.prompt) {
                            case 'none':
                                if (!isLoggedIn)
                                    return failOAuth(401, 'login_required', 'user must be logged in interactively, cannot authorize without logged in user.', next);
                                return local.authorizeFlow(req, res, next);
                            case 'login':
                                // Force login; wipe session data
                                if (isLoggedIn) {
                                    delete req.session[authMethodId].userInfo;
                                    isLoggedIn = false;
                                }
                                break;
                        }
                    }
                    // We're fine. Check for pre-existing sessions.
                    if (isLoggedIn)
                        return local.authorizeFlow(req, res, next);
                    // Not logged in, or forced login
                    return local.renderLogin(req, res, apiId);
                });
        });
    });

    local.loginUser = function (username, password, callback) {
        wicked.apiPost('login', {
            username: username,
            password: password
        }, function (err, userInfoList) {
            if (err)
                return callback(err);

            // TODO: Real profile, for now userInfo from wicked...
            const userInfo = userInfoList[0];
            debug('Login successful, userInfo: ' + JSON.stringify(userInfo));
            
            return utils.wickedUserInfoToOidcProfile(userInfo, callback);
        });
    };

    local.authorizeFlow = function (req, res, next) {
        debug('authorizeFlow()');
        const authRequest = req.session[authMethodId].authRequest;
        const userInfo = req.session[authMethodId].userInfo;

        debug('/authorize/login: Calling authorization end point.');
        oauth2.authorize({
            response_type: authRequest.response_type,
            authenticated_userid: userInfo.sub,
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
            profileStore.registerTokenOrCode(redirectUri, authRequest.api_id, userInfo, (err) => {
                if (err)
                    return failError(500, err, next);
                if (authRequest.state)
                    uri += '&state=' + qs.escape(authRequest.state);
                return res.redirect(uri);
            });
        });
    };

    local.post('/api/:apiId/authorize/login', csrfProtection, function (req, res, next) {
        const apiId = req.params.apiId;
        debug(`POST /api/${apiId}/authorize/login`);

        const username = req.body.username;
        const password = req.body.password;
        debug(`username: ${username}, password: ${password}`);

        local.loginUser(username, password, function (err, userInfo) {
            if (err) {
                return local.renderLogin(req, res, apiId, 'Username or password invalid.');
            }

            // This is where we get the profile when interactively logging in
            req.session[authMethodId].userInfo = userInfo;

            local.authorizeFlow(req, res, next);
        });
    });

    local.post('/api/:apiId/token', function (req, res, next) {
        const apiId = req.params.apiId;
        debug(`/api/${apiId}/token`);
        // Full switch/case on things to do, for all flows
        // - Client Credentials -> Go to Kong and get a token
        // - Authorization Code -> Go to Kong and get a token
        // - Resource Owner Password Grant --> Check username/password/client id/secret and get a token
        // - Refresh Token --> Check validity of user and client --> Get a token

        const tokenRequest = utils.makeTokenRequest(req, apiId, authMethodId);
        utils.validateTokenRequest(tokenRequest, function (err, validationResult) {
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
                    return utils.tokenClientCredentials(tokenRequest, handleTokenResult);
                case 'authorization_code':
                    // Use the generic version here as well
                    return utils.tokenAuthorizationCode(tokenRequest, handleTokenResult);
                case 'password':
                    // This has to be done specifically
                    return local.tokenPasswordGrant(tokenRequest, handleTokenResult);
                case 'refresh_token':
                    // This as well
                    return local.tokenRefreshToken(tokenRequest, handleTokenResult);
            }
            // This should not be possible
            return failOAuth(400, 'unsupported_grant_type', `invalid grant type ${tokenRequest.grant_type}`);
        });
    });

    local.tokenPasswordGrant = function (tokenRequest, callback) {
        debug('tokenPasswordGrant()');
        // Let's validate the subscription first...
        utils.validateSubscription(tokenRequest.client_id, tokenRequest.api_id, function (err, validationResult) {
            if (err)
                return callback(err);
            const trustedSubscription = validationResult.trusted;
            // Now we know whether we have a trusted subscription or not; only allow trusted subscriptions to
            // retrieve a token via the password grant.
            if (!trustedSubscription)
                return failOAuth(400, 'invalid_request', 'only trusted application subscriptions can retrieve tokens via the password grants.', callback);
            utils.validateApiScopes(tokenRequest.api_id, tokenRequest.scope, trustedSubscription, function (err, validatedScopes) {
                if (err)
                    return failOAuth(500, 'server_error', 'could not validate requested token scope', err, callback);
                // Update the scopes
                tokenRequest.scope = validatedScopes.validatedScopes;

                local.loginUser(tokenRequest.username, tokenRequest.password, function (err, userInfo) {
                    if (err) {
                        // Don't answer wrong logins immediately please.
                        return setTimeout(() => {
                            return failOAuth(err.statusCode, 'invalid_request', 'invalid username or password', callback);
                        }, 500);
                    }
                    // This was fine. Now check if we can issue a token.
                    tokenRequest.authenticated_userid = userInfo.sub;
                    tokenRequest.session_data = userInfo;
                    oauth2.token(tokenRequest, callback);
                });
            });
        });
    };

    local.tokenRefreshToken = function (tokenRequest, callback) {
        debug('tokenRefreshToken()');
        // Client validation and all that stuff can be done in the OAuth2 adapter,
        // but we still need to verify that the user for which the refresh token was
        // created is still a valid user.
        const refreshToken = tokenRequest.refresh_token;
        tokens.getTokenDataByRefreshToken(refreshToken, function (err, tokenInfo) {
            if (err)
                return failOAuth(400, 'invalid_request', 'could not retrieve information on the given refresh token.', err, callback);
            debug('refresh token info:');
            debug(tokenInfo);
            const userId = tokenInfo.authenticated_userid;
            if (!userId)
                return failOAuth(500, 'server_error', 'could not correctly retrieve authenticated user id from refresh token', callback);
            wicked.apiGet('users/' + userId, function (err, userInfo) {
                if (err)
                    return failOAuth(400, 'invalid_request', 'user associated with refresh token is not a valid user (anymore)', err, callback);
                debug('wicked local user info:');
                debug(userInfo);
                utils.wickedUserInfoToOidcProfile(userInfo, function (err, oidcProfile) {
                    if (err)
                        return failOAuth(500, 'server_error', 'could not convert wicked profile to OIDC profile', err, callback);
                    tokenRequest.session_data = oidcProfile;
                    // Now delegate to oauth2 adapter:
                    oauth2.token(tokenRequest, callback);
                });
            });
        });
    };

    local.get('/api/:apiId/profile', utils.getProfile(authMethodId));

    return local;
};
