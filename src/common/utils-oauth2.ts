'use strict';

import { OidcProfile, WickedApiScopes, WickedUserInfo, WickedPool, Callback } from "wicked-sdk";
import { WickedApiScopesCallback, AuthRequest, SubscriptionValidationCallback, ValidatedScopes, TokenRequest, SimpleCallback, AccessTokenCallback, AuthResponse, SubscriptionValidation, OAuth2Request } from "./types";

const async = require('async');
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:utils-oauth2');
import * as wicked from 'wicked-sdk';
const request = require('request');

import { failMessage, failError, failOAuth, makeError } from './utils-fail';
import { profileStore } from './profile-store';

import { utils } from './utils';
import { oauth2 } from '../kong-oauth2/oauth2';

export class UtilsOAuth2 {

    constructor() {
        debug(`UtilsOAuth2()`);
    }

    private _apiScopes: { [apiId: string]: WickedApiScopes } = {};
    public getApiScopes = (apiId: string, callback: WickedApiScopesCallback) => {
        debug(`getApiScopes(${apiId})`);
        const instance = this;
        // Check cache first
        if (this._apiScopes[apiId])
            return callback(null, this._apiScopes[apiId]);
        debug('getApiScopes: Not present in cache, fetching.');
        wicked.getApi(apiId, function (err, apiInfo) {
            if (err) {
                debug('getApiScopes: Fetching API scopes errored.');
                debug(err);
                return callback(err);
            }
            // TBD: Is it good to return an error here?
            if (!apiInfo || !apiInfo.settings)
                return callback(new Error(`API ${apiId} does not have settings section`));
            debug('getApiScopes: Succeeded, storing.');
            debug('api.settings.scopes: ' + JSON.stringify(apiInfo.settings.scopes));
            instance._apiScopes[apiId] = apiInfo.settings.scopes || {};
            return callback(null, instance._apiScopes[apiId]);
        });
    };

    public validateAuthorizeRequest = (authRequest: AuthRequest, callback: SubscriptionValidationCallback) => {
        debug(`validateAuthorizeRequest(${authRequest})`);
        if (authRequest.response_type !== 'token' &&
            authRequest.response_type !== 'code')
            return failMessage(400, `Invalid response_type ${authRequest.response_type}`, callback);
        if (!authRequest.client_id)
            return failMessage(400, 'Invalid or empty client_id.', callback);
        if (!authRequest.redirect_uri)
            return failMessage(400, 'Invalid or empty redirect_uri', callback);
        this.validateSubscription(authRequest, function (err, subsValidation: SubscriptionValidation) {
            if (err)
                return failMessage(400, err.message, callback);
            const application = subsValidation.subsInfo.application;
            if (!application.redirectUri)
                return failMessage(400, 'The application associated with the given client_id does not have a registered redirect_uri.', callback);

            // Verify redirect_uri from application, has to match what is passed in
            const uri1 = utils.normalizeRedirectUri(authRequest.redirect_uri);
            const uri2 = utils.normalizeRedirectUri(subsValidation.subsInfo.application.redirectUri);

            if (uri1 !== uri2) {
                error(`Expected redirect_uri: ${uri2}`);
                error(`Received redirect_uri: ${uri1}`);
                return failMessage(400, 'The provided redirect_uri does not match the registered redirect_uri', callback);
            }
            // Now we have a redirect_uri; we can now make use of failOAuth

            // Check for PKCE for public apps using the authorization code grant
            if (authRequest.response_type === 'code' &&
                application.confidential !== true) {
                if (!authRequest.code_challenge)
                    return failOAuth(400, 'invalid_request', 'the given client is a public client; it must present a code_challenge (PKCE, RFC7636) to use the authorization code grant.', callback);
                if (!authRequest.code_challenge_method)
                    authRequest.code_challenge_method = 'plain'; // Default
                if (authRequest.code_challenge_method !== 'plain' &&
                    authRequest.code_challenge_method !== 'S256')
                    return failOAuth(400, 'invalid_request', 'unsupported code_challenge_method; expected "plain" or "S256".', callback);
            }

            // Success
            return callback(null, subsValidation);
        });
    };

    public validateSubscription = (oauthRequest: OAuth2Request, callback: SubscriptionValidationCallback) => {
        debug('validateSubscription()');
        wicked.getSubscriptionByClientId(oauthRequest.client_id, oauthRequest.api_id, (err, subsInfo) => {
            if (err)
                return failOAuth(400, 'invalid_request', 'could not validate client_id and API subscription', err, callback);
            // Do we have a trusted subscription?
            let trusted = false;
            if (subsInfo.subscription && subsInfo.subscription.trusted) {
                debug('validateAuthorizeRequest: Trusted subscription detected.');
                // Yes, note that in the authRequest
                trusted = true;
            }
            if (!subsInfo.application || !subsInfo.application.id)
                return failOAuth(500, 'server_error', 'Subscription information does not contain a valid application id', callback);

            oauthRequest.app_id = subsInfo.application.id;
            oauthRequest.app_name = subsInfo.application.name;
            const returnValues: SubscriptionValidation = {
                subsInfo: subsInfo,
                trusted: trusted,
            };

            return callback(null, returnValues); // All's good for now
        });
    };

    public validateApiScopes = (apiId: string, scope: string, subIsTrusted: boolean, callback: Callback<ValidatedScopes>) => {
        debug(`validateApiScopes(${apiId}, ${scope})`);

        async.parallel({
            apiScopes: callback => this.getApiScopes(apiId, callback),
            apiInfo: callback => utils.getApiInfo(apiId, callback),
        }, (err, results) => {
            if (err)
                return failError(500, err, callback);
            const apiScopes = results.apiScopes as WickedApiScopes;

            let requestScope = scope;
            if (!requestScope) {
                debug('validateApiScopes: No scopes requested.');
                requestScope = '';
            }

            let scopes = [] as string[];
            if (requestScope) {
                if (requestScope.indexOf(' ') > 0)
                    scopes = requestScope.split(' ');
                else if (requestScope.indexOf(',') > 0)
                    scopes = requestScope.split(',');
                else if (requestScope.indexOf(';') > 0)
                    scopes = requestScope.split(';')
                else
                    scopes = [requestScope];
                debug(scopes);
            } else {
                scopes = [];
            }
            const validatedScopes = [] as string[];
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

    public makeTokenRequest(req, apiId: string, authMethodId: string): TokenRequest {
        // Gather parameters from body. Note that not all parameters
        // are used in all flows.
        const tokenRequest = {
            api_id: apiId,
            auth_method: req.app.get('server_name') + ':' + authMethodId,
            grant_type: req.body.grant_type,
            code: req.body.code,
            //redirect_uri: req.body.redirect_uri,
            client_id: req.body.client_id,
            client_secret: req.body.client_secret,
            scope: req.body.scope,
            username: req.body.username,
            password: req.body.password,
            refresh_token: req.body.refresh_token,
            // PKCE
            code_verifier: req.body.code_verifier
        };
        if (!tokenRequest.client_id) {
            // Check for Basic Auth
            const authHeader = req.get('Authorization');
            if (authHeader) {
                let basicAuth = authHeader;
                if (authHeader.toLowerCase().startsWith('basic')) {
                    const spacePos = authHeader.indexOf(' ');
                    basicAuth = authHeader.substring(spacePos + 1);
                }
                // Try to decode base 64 to get client_id and client_secret
                try {
                    const idAndSecret = utils.decodeBase64(basicAuth);
                    // client_id:client_secret
                    const colonIndex = idAndSecret.indexOf(':');
                    if (colonIndex > 0) {
                        tokenRequest.client_id = idAndSecret.substring(0, colonIndex);
                        tokenRequest.client_secret = idAndSecret.substring(colonIndex + 1);
                    } else {
                        warn('makeTokenRequest: Received invalid client_id and client_secret in as Basic Auth')
                    }
                } catch (err) {
                    error('Received Basic Auth credentials, but they are invalid')
                    error(err);
                }
            }
        }

        return tokenRequest;
    };

    public validateTokenRequest = (tokenRequest: TokenRequest, callback: SimpleCallback) => {
        debug(`validateTokenRequest(${tokenRequest})`);

        if (!tokenRequest.grant_type)
            return failOAuth(400, 'invalid_request', 'grant_type is missing.', callback);

        // Different for different grant_types
        if (tokenRequest.grant_type === 'client_credentials') {
            if (!tokenRequest.client_id)
                return failOAuth(400, 'invalid_client', 'client_id is missing.', callback);
            if (!tokenRequest.client_secret)
                return failOAuth(400, 'invalid_client', 'client_secret is missing.', callback);
            return callback(null);
        } else if (tokenRequest.grant_type === 'authorization_code') {
            if (!tokenRequest.code)
                return failOAuth(400, 'invalid_request', 'code is missing.', callback);
            if (!tokenRequest.client_id)
                return failOAuth(400, 'invalid_client', 'client_id is missing.', callback);
            if (!tokenRequest.client_secret && !tokenRequest.code_verifier) {
                return failOAuth(400, 'invalid_client', 'client_secret or code_verifier is missing.', callback);
            }
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

    public tokenClientCredentials = (tokenRequest: TokenRequest, callback: AccessTokenCallback) => {
        debug('tokenClientCredentials()');
        const instance = this;
        this.validateSubscription(tokenRequest, (err, validationResult) => {
            if (err)
                return callback(err);
            instance.validateApiScopes(tokenRequest.api_id, tokenRequest.scope, validationResult.trusted, (err, scopeInfo) => {
                if (err)
                    return callback(err);
                tokenRequest.scope = scopeInfo.validatedScopes;
                // We can just pass this on to the wicked SDK.
                oauth2.token(tokenRequest, callback);
            });
        });
    };

    public tokenAuthorizationCode = (tokenRequest: TokenRequest, callback: AccessTokenCallback) => {
        debug('tokenAuthorizationCode()');
        profileStore.retrieve(tokenRequest.code, (err, profile) => {
            if (err)
                return callback(err);
            tokenRequest.code_challenge = profile.code_challenge;
            tokenRequest.code_challenge_method = profile.code_challenge_method;
            delete profile.code_challenge;
            delete profile.code_challenge_method;
            // We can just pass this on to the wicked SDK, and the register the token.
            oauth2.token(tokenRequest, (err, accessToken) => {
                if (err)
                    return callback(err);
                accessToken.session_data = profile;
                // We now have to register the access token with the profile
                // Also delete the code from the redis, it's not needed anymore
                async.parallel({
                    deleteToken: (callback) => {
                        // We'll ignore what happens here.
                        profileStore.deleteTokenOrCode(tokenRequest.code);
                        return callback(null);
                    },
                    updateToken: (callback) => {
                        profileStore.registerTokenOrCode(accessToken, tokenRequest.api_id, profile, (err) => {
                            if (err)
                                return callback(err);
                            return callback(null, accessToken);
                        });
                    }
                }, (err, results) => {
                    if (err)
                        return callback(err);
                    return callback(null, accessToken);
                });
            });
        });
    }

    public getProfile(req, res, next) {
        debug(`/profile`);
        // OIDC profile end point, we need this. This is nice. Yeah.
        // res.status(500).json({ message: 'Not yet implemented.' });

        const bearerToken = req.get('authorization');
        if (!bearerToken)
            return failMessage(401, 'Unauthorized', next);
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
    }

    public wickedUserInfoToOidcProfile(userInfo: WickedUserInfo): OidcProfile {
        debug('wickedUserInfoToOidcProfile()');
        // Simple mapping to some basic OIDC profile claims
        const oidcProfile = {
            sub: userInfo.id,
            email: userInfo.email,
            email_verified: userInfo.validated
        };
        return oidcProfile;
    };

    public makeOidcProfile = (poolId: string, authResponse: AuthResponse, regInfo, callback) => {
        debug(`makeOidcProfile(${poolId}, ${authResponse.userId})`);
        const userId = authResponse.userId;
        const instance = this;

        // OK; we might be able to get the information from somewhere else, but let's keep
        // it simple.
        async.parallel({
            userInfo: callback => wicked.getUser(userId, callback),
            poolInfo: callback => utils.getPoolInfo(poolId, callback)
        }, function (err, results) {
            if (err)
                return callback(err);
            const userInfo = results.userInfo as WickedUserInfo;
            const poolInfo = results.poolInfo as WickedPool;

            const profile = instance.wickedUserInfoToOidcProfile(userInfo);
            // Now let's see what we can map from the registration
            for (let i = 0; i < poolInfo.properties.length; ++i) {
                const propInfo = poolInfo.properties[i];
                const propName = propInfo.id;
                if (!regInfo[propName])
                    continue;
                // If the property doesn't include a mapping to an OIDC claim, we can't use it
                if (!propInfo.oidcClaim)
                    continue;
                // Now assign the value to the OIDC claim in the profile
                profile[propInfo.oidcClaim] = regInfo[propName];
            }

            debug('makeOidcProfile() assembled the following profile:');
            debug(profile);

            return callback(null, profile);
        });
    }
};

export const utilsOAuth2 = new UtilsOAuth2();
