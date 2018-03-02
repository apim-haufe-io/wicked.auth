'use strict';

const debug = require('debug')('portal-auth:utils-oauth2');
const wicked = require('wicked-sdk');
const request = require('request');

const { failMessage, failError, failOAuth, makeError } = require('./utils-fail');
const profileStore = require('./profile-store');

const oauth2 = require('../kong-oauth2/oauth2');
const tokens = require('../kong-oauth2/tokens');

const utilsOAuth2 = function() {};

utilsOAuth2._apiScopes = {};
utilsOAuth2.getApiScopes = function (apiId, callback) {
    debug(`getApiScopes(${apiId})`);
    // Check cache first
    if (utilsOAuth2._apiScopes[apiId])
        return callback(null, utilsOAuth2._apiScopes[apiId]);
    debug('getApiScopes: Not present in cache, fetching.');
    wicked.apiGet(`apis/${apiId}`, function (err, api) {
        if (err) {
            debug('getApiScopes: Fetching API scopes errored.');
            debug(err);
            return callback(err);
        }
        // TBD: Is it good to return an error here?
        if (!api || !api.settings)
            return callback(new Error(`API ${apiId} does not have settings section`));
        debug('getApiScopes: Succeeded, storing.');
        debug('api.settings.scopes: ' + JSON.stringify(api.settings.scopes));
        utilsOAuth2._apiScopes[apiId] = api.settings.scopes || {};
        return callback(null, utilsOAuth2._apiScopes[apiId]);
    });
};

utilsOAuth2.validateAuthorizeRequest = function (authRequest, callback) {
    debug(`validateAuthorizeRequest(${authRequest})`);
    if (authRequest.response_type !== 'token' &&
        authRequest.response_type !== 'code')
        return failMessage(400, `Invalid response_type ${authRequest.response_type}`, callback);
    if (!authRequest.client_id)
        return failMessage(400, 'Invalid or empty client_id.', callback);
    return utilsOAuth2.validateSubscription(authRequest.client_id, authRequest.api_id, callback);
};

utilsOAuth2.validateSubscription = function (clientId, apiId, callback) {
    debug('validateSubscription()');
    wicked.getSubscriptionByClientId(clientId, apiId, function (err, subsInfo) {
        if (err)
            return failOAuth(400, 'invalid_request', 'could not validate client_id and API subscription', err, callback);
        // Do we have a trusted subscription?
        let trusted = false;
        if (subsInfo.subscription && subsInfo.subscription.trusted) {
            debug('validateAuthorizeRequest: Trusted subscription detected.');
            // Yes, note that in the authRequest
            trusted = true;
        }
        const returnValues = {
            trusted: trusted
        };

        return callback(null, returnValues); // All's good for now
    });
};

utilsOAuth2.validateApiScopes = function (apiId, scope, subIsTrusted, callback) {
    debug(`validateApiScopes(${apiId}, ${scope})`);

    utilsOAuth2.getApiScopes(apiId, function (err, apiScopes) {
        if (err)
            return failError(500, err, callback);

        let requestScope = scope;
        if (!requestScope) {
            debug('validateApiScopes: No scopes requested.');
            requestScope = '';
        }

        let scopes;
        if (requestScope)
            scopes = requestScope.split(' ');
        else
            scopes = [];

        const validatedScopes = [];
        // Pass upstream if we changed the scopes (e.g. for a trusted application)
        let scopesDiffer = false;
        if (!subIsTrusted) {
            debug('validateApiScopes: Non-trusted subscription.');
            for (let i = 0; i < scopes.length; ++i) {
                const thisScope = scopes[i];
                if (!apiScopes[thisScope])
                    return failMessage(400, `Invalid or unknown scope "${thisScope}".`, callback);
                validatedScopes.push(thisScope);
            }
        } else {
            debug('validateApiScopes: Trusted subscription.');
            // apiScopes is a map of scopes
            for (let aScope in apiScopes) {
                validatedScopes.push(aScope);
            }
            scopesDiffer = true;
        }
        debug(`validated Scopes: ${validatedScopes}`);

        return callback(null, {
            scopesDiffer: scopesDiffer,
            validatedScopes: validatedScopes
        });
    });
};

utilsOAuth2.makeTokenRequest = function (req, apiId, authMethodId) {
    // Gather parameters from body. Note that not all parameters
    // are used in all flows.
    return {
        api_id: apiId,
        auth_method: req.app.get('server_name') + ':' + authMethodId,
        grant_type: req.body.grant_type,
        code: req.body.code,
        redirect_uri: req.body.redirect_uri,
        client_id: req.body.client_id,
        client_secret: req.body.client_secret,
        scope: req.body.scope,
        username: req.body.username,
        password: req.body.password,
        refresh_token: req.body.refresh_token
    };
};

utilsOAuth2.validateTokenRequest = function (tokenRequest, callback) {
    debug(`validateTokenRequest(${tokenRequest})`);

    if (!tokenRequest.grant_type)
        return failOAuth(400, 'invalid_request', 'grant_type is missing.', callback);

    // Different for different grant_types
    if (tokenRequest.grant_type === 'client_credentials') {
        if (!tokenRequest.client_id)
            return failOAuth(400, 'invalid_client', 'client_id is missing.', callback);
        if (!tokenRequest.client_secret)
            return failOAuth(400, 'invalid_client', 'client_secret is missing.', callback);
        return callback(null, {});
    } else if (tokenRequest.grant_type === 'authorization_code') {
        if (!tokenRequest.code)
            return failOAuth(400, 'invalid_request', 'code is missing.', callback);
        if (!tokenRequest.client_id)
            return failOAuth(400, 'invalid_client', 'client_id is missing.', callback);
        if (!tokenRequest.client_secret)
            return failOAuth(400, 'invalid_client', 'client_secret is missing.', callback);
    } else if (tokenRequest.grant_type === 'password') {
        if (!tokenRequest.client_id)
            return failOAuth(400, 'invalid_client', 'client_id is missing.', callback);
        // For confidential clients, the client_secret will also be checked (by the OAuth2 adapter)
        if (!tokenRequest.username)
            return failOAuth(400, 'invalid_request', 'username is missing.', callback);
        if (!tokenRequest.username)
            return failOAuth(400, 'invalid_request', 'password is missing.', callback);
        // TODO: scopes
    } else if (tokenRequest.grant_type === 'refresh_token') {
        if (!tokenRequest.client_id)
            return failOAuth(400, 'invalid_client', 'client_id is missing.', callback);
        // For confidential clients, the client_secret will also be checked (by the OAuth2 adapter)
        if (!tokenRequest.refresh_token)
            return failOAuth(400, 'invalid_request', 'refresh_token is missing.', callback);
    } else {
        return failOAuth(400, 'unsupported_grant_type', `The grant_type '${tokenRequest.grant_type}' is not supported or is unknown.`, callback);
    }
    return callback(null);
};

utilsOAuth2.tokenClientCredentials = function (tokenRequest, callback) {
    debug('tokenClientCredentials()');
    // We can just pass this on to the wicked SDK.
    oauth2.token(tokenRequest, callback);
};

utilsOAuth2.tokenAuthorizationCode = function (tokenRequest, callback) {
    debug('tokenAuthorizationCode()');
    // We can just pass this on to the wicked SDK, and the register the token.
    oauth2.token(tokenRequest, (err, accessToken) => {
        if (err)
            return callback(err);
        profileStore.retrieve(tokenRequest.code, (err, profile) => {
            if (err)
                return callback(err);
            accessToken.session_data = profile;
            return callback(null, accessToken);
        });
        //     (profile, callback) => profileStore.registerTokenOrCode(accessToken, tokenRequest.api_id, profile, callback)
        // ], (err) => {
        //     if (err)
        //         return callback(err);
        //     return callback(null, accessToken);
        // });
    });
};

utilsOAuth2.getProfile = function (req, res, next) {
    debug(`/profile`);
    // OIDC profile end point, we need this. This is nice. Yeah.
    // res.status(500).json({ message: 'Not yet implemented.' });

    const bearerToken = req.get('authorization');
    if (!bearerToken)
        return failMessage(403, 'Unauthorized', next);
    let accessToken = null;
    if (bearerToken.indexOf(' ') > 0) {
        // assume Bearer xxx
        let tokenSplit = bearerToken.split(' ');
        if (tokenSplit.length !== 2)
            return failOAuth(400, 'invalid_request', 'Invalid Bearer token.', next);
        accessToken = bearerToken.split(' ')[1];
    } else {
        // Assume without "Bearer", just the access token
        accessToken = bearerToken;
    }
    accessToken = accessToken.trim();

    // Read from profile store.
    profileStore.retrieve(accessToken, (err, profile) => {
        if (err || !profile)
            return failOAuth(404, 'invalid_request', 'Not found', next);
        return res.status(200).json(profile);
    });
};

function makeFullName(userInfo) {
    if (userInfo.firstName && userInfo.lastName)
        return `${userInfo.firstName} ${userInfo.lastName}`;
    else if (userInfo.lastName)
        return userInfo.lastName;
    else if (userInfo.firstName)
        return userInfo.firstName;
    return "No Name";
}

utilsOAuth2.wickedUserInfoToOidcProfile = function (userInfo, callback) {
    debug('wickedUserInfoToOidcProfile()');
    // This is subject to heavy change, possibly and probably, and
    // will also consist of fetching a profile/registration info from
    // the wicked API.
    const oidcProfile = {
        sub: userInfo.id,
        email: userInfo.email,
        email_verified: userInfo.validated,
        name: makeFullName(userInfo),
        given_name: userInfo.firstName,
        family_name: userInfo.lastName
        // admin: userInfo.admin // No no noooo
    };
    return callback(null, oidcProfile);
};

// Whoa, this is closures galore.
// utils.verifyClientAndAuthenticate = function (idpName, passportAuthenticate) {
//     return function (req, res, next) {
//         const apiId = req.params.apiId;
//         const clientId = req.query.client_id;
//         const responseType = req.query.response_type;
//         const givenRedirectUri = req.query.redirect_uri;
//         const givenState = req.query.state;
//         debug('/' + idpName + '/api/' + apiId + '?client_id=' + clientId + '&response_type=' + responseType);
//         if (givenState)
//             debug('given state: ' + givenState);

//         if (!clientId)
//             return next(makeError('Bad request. Query parameter client_id is missing.', 400));
//         if (responseType !== 'token' && responseType !== 'code')
//             return next(makeError('Bad request. Parameter response_type is missing or faulty. Only "token" and "code" are supported.', 400));
//         // Check whether we need to bother Google or not.
//         wicked.getSubscriptionByClientId(clientId, apiId, function (err, subsInfo) {
//             if (err)
//                 return next(err);

//             // console.log(JSON.stringify(subsInfo, null, 2));

//             // Yes, we have a valid combination of API and Client ID
//             // Store data in the session.
//             const redirectUri = subsInfo.application.redirectUri;

//             if (givenRedirectUri && givenRedirectUri !== redirectUri)
//                 return next(makeError('Bad request. redirect_uri mismatch.', 400));

//             req.session.apiId = apiId;
//             req.session.clientId = clientId;
//             req.session.redirectUri = redirectUri;
//             req.session.responseType = responseType;
//             if (givenState)
//                 req.session.state = givenState;
//             else if (req.session.state)
//                 delete req.session.state;

//             req.session.userValid = false;

//             // Remember the host of the redirectUri to allow CORS from it:
//             storeRedirectUriForCors(redirectUri);

//             // Off you go with passport:
//             passportAuthenticate(req, res, next);
//         });
//     };
// };

// utils.authorizeAndRedirect = function (idpName, authServerName) {
//     return function (req, res, next) {
//         debug('/' + idpName + '/callback');

//         if (!req.session ||
//             !req.session.passport ||
//             !req.session.passport.user ||
//             !req.session.passport.user.id)
//             return next(makeError('Could not retrieve authenticated user id from session.', 500));

//         const authenticatedUserId = req.session.passport.user.id;
//         const clientId = req.session.clientId;
//         const apiId = req.session.apiId;
//         const responseType = req.session.responseType;

//         // This shouldn't happen...
//         if (!clientId || !apiId || !responseType)
//             return next(makeError('Invalid state, client_id, response_type and/or API id not known.', 500));

//         // Now get a token puhlease.
//         // Note: We don't use scopes here.
//         const userInfo = {
//             authenticated_userid: authenticatedUserId,
//             client_id: clientId,
//             api_id: apiId,
//             auth_server: authServerName
//         };
//         let authorize = wicked.oauth2GetAuthorizationCode; // responseType === 'code'
//         if (responseType === 'token')
//             authorize = wicked.oauth2AuthorizeImplicit;

//         authorize(userInfo, function (err, result) {
//             if (err)
//                 return next(err);
//             if (!result.redirect_uri)
//                 return next(makeError('Did not receive a redirect_uri from Kong Adapter.', 500));
//             // Yay
//             req.session.userValid = true;

//             let clientRedirectUri = result.redirect_uri;
//             // If we were passed a state, give that state back
//             if (req.session.state)
//                 clientRedirectUri += '&state=' + req.session.state;

//             // Redirect back, for the token response, the access token is in the
//             // fragment of the URI. For the code response, the code is in the query
//             // of the URI
//             res.redirect(clientRedirectUri);
//         });
//     };
// };

module.exports = utilsOAuth2;