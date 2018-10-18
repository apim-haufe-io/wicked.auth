'use strict';

import { GenericOAuth2Router } from '../common/generic-router';
import { AuthRequest, EndpointDefinition, AuthResponse, IdentityProvider, IdpOptions, OAuth2IdpConfig, ExpressHandler, CheckRefreshDecision } from '../common/types';
import { OidcProfile, Callback, WickedApi } from 'wicked-sdk';
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:oauth2');

const Router = require('express').Router;
const passport = require('passport');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var jwt = require('jsonwebtoken');

import { utils } from '../common/utils';
import { failMessage, failError, failOAuth, makeError } from '../common/utils-fail';

/**
 * This is a sample of how an IdP must work to be able to integrate into
 * the generic OAuth2 workflow in generic.js
 */
export class OAuth2IdP implements IdentityProvider {

    private genericFlow: GenericOAuth2Router;
    private basePath: string;
    private authMethodId: string;
    private options: IdpOptions;
    private authMethodConfig: OAuth2IdpConfig;

    private authenticateWithOAuth2: ExpressHandler;
    private authenticateCallback: ExpressHandler;

    constructor(basePath: string, authMethodId: string, authMethodConfig: any, options: IdpOptions) {
        debug(`constructor(${basePath}, ${authMethodId},...)`);
        this.genericFlow = new GenericOAuth2Router(basePath, authMethodId);

        this.basePath = basePath;
        this.authMethodId = authMethodId;
        this.authMethodConfig = authMethodConfig;

        // Verify configuration
        if (!authMethodConfig.clientId)
            throw new Error(`OAuth2 auth method "${authMethodId}": In auth method configuration, property "config", the property "clientId" is missing.`);
        if (!authMethodConfig.clientSecret)
            throw new Error(`OAuth2 auth method "${authMethodId}": In auth-server configuration, property "config", the property "clientSecret" is missing.`);

        if (!authMethodConfig.endpoints)
            throw new Error(`OAuth2 auth method ${authMethodId}: In auth method configuration, property, config, the property "endpoints" is missing.`);
        if (!authMethodConfig.endpoints.authorizeEndpoint)
            throw new Error(`OAuth2 auth method ${authMethodId}: In auth method configuration, property, config, the property "endpoints.authorizeEndpoint" is missing.`);
        if (!authMethodConfig.endpoints.tokenEndpoint)
            throw new Error(`OAuth2 auth method ${authMethodId}: In auth method configuration, property, config, the property "endpoints.tokenEndpoint" is missing.`);

        // Assemble the callback URL
        const callbackUrl = `${options.externalUrlBase}/${authMethodId}/callback`;
        info(`OAuth2 Authentication: Expected callback URL: ${callbackUrl}`);

        const oauthStrategy = new OAuth2Strategy({
            authorizationURL: authMethodConfig.endpoints.authorizeEndpoint,
            tokenURL: authMethodConfig.endpoints.tokenEndpoint,
            clientID: authMethodConfig.clientId,
            clientSecret: authMethodConfig.clientSecret,
            callbackURL: callbackUrl,
            passReqToCallback: true
        }, this.verifyProfile);

        if (authMethodConfig.resource || authMethodConfig.params) {
            let params: any = {};
            if (authMethodConfig.params)
                params = Object.assign({}, authMethodConfig.params);
            if (authMethodConfig.resource)
                params.resource = authMethodConfig.resource;

            // ADFS Mode
            oauthStrategy.authorizationParams = function (option) {
                return params;
            };
        }

        oauthStrategy.userProfile = function (accessToken, done) {
            done(null, accessToken);
        };

        passport.use(authMethodId, oauthStrategy);

        let scope: string[] = null;
        if (authMethodConfig.endpoints.authorizeScope) {
            scope = authMethodConfig.endpoints.authorizeScope.split(' ');
        }
        const authenticateSettings = {
            session: false,
            scope: scope,
            failureRedirect: `${options.basePath}/failure`
        };

        this.authenticateWithOAuth2 = passport.authenticate(authMethodId, authenticateSettings);
        this.authenticateCallback = passport.authenticate(authMethodId, authenticateSettings);

        this.genericFlow.initIdP(this);
    }

    public getType() {
        return "oauth2";
    }

    public getRouter() {
        return this.genericFlow.getRouter();
    }

    private verifyProfile = (req, accessToken, refreshTokenNotUsed, profileNotUsed, done) => {
        debug(`verifyProfile(${this.authMethodId})`);

        let profile;
        // Verify signing?
        try {
            if (this.authMethodConfig.certificate) {
                // Decode Oauth token and verify that it has been signed by the given public cert
                debug(`verifyProfile(${this.authMethodId}): Verifying JWT signature and decoding profile`);
                profile = jwt.verify(accessToken, this.authMethodConfig.certificate);
                debug(`verifyProfile(${this.authMethodId}): Verified JWT successfully`);
            } else {
                // Do not check signing, just decode
                warn(`verifyProfile(${this.authMethodId}): Decoding JWT signature, NOT verifying signature, "certificate" not specified`)
                profile = jwt.decode(accessToken);
            }
        } catch (ex) {
            error(`verifyProfile(${this.authMethodId}): JWT decode/verification failed.`);
            return done(null, false, { message: ex });
        }

        debug(`verifyProfile(${this.authMethodId}): Decoded JWT Profile:`);
        debug(profile);

        try {
            const authResponse = this.createAuthResponse(profile);
            return done(null, authResponse);
        } catch (err) {
            return done(null, false, { message: err });
        }
    };

    /**
     * In case the user isn't already authenticated, this method will
     * be called from the generic flow implementation. It is assumed to
     * initiate an authentication of the user by whatever means is
     * suitable, depending on the actual Identity Provider implementation.
     * 
     * If you need additional end points responding to any of your workflows,
     * register them with the `endpoints()` method below.
     * 
     * `authRequest` contains information on the authorization request,
     * in case those are needed (such as for displaying information on the API
     * or similar).
     */
    public authorizeWithUi(req, res, next, authRequest: AuthRequest) {
        // Do your thing...
        return this.authenticateWithOAuth2(req, res);
    };

    /**
     * In case you need additional end points to be registered, pass them
     * back to the generic flow implementation here; they will be registered
     * as "/<authMethodName>/<uri>", and then request will be passed into
     * the handler function, which is assumed to be of the signature
     * `function (req, res, next)` (the standard Express signature)
     */
    public endpoints(): EndpointDefinition[] {
        // This is just a sample endpoint; usually this will be like "callback",
        // e.g. for OAuth2 callbacks or similar.
        return [
            {
                method: 'get',
                uri: '/callback',
                middleware: this.authenticateCallback,
                handler: this.callbackHandler
            }
        ];
    };

    /**
     * Verify username and password and return the data on the user, like
     * when authorizing via some 3rd party. If this identity provider cannot
     * authenticate via username and password, an error will be returned.
     * 
     * @param {*} user Username
     * @param {*} pass Password
     * @param {*} callback Callback method, `function(err, authenticationData)`
     */
    public authorizeByUserPass(user: string, pass: string, callback: Callback<AuthResponse>) {
        // Verify username and password, if possible.
        // For Github, this is not possible, so we will just return an
        // error message.
        return failOAuth(400, 'unsupported_grant_type', 'The generic OAuth2 provider does not support authorizing headless with username and password', callback);
    };

    public checkRefreshToken(tokenInfo, apiInfo: WickedApi, callback: Callback<CheckRefreshDecision>) {
        // Decide whether it's okay to refresh this token or not, e.g.
        // by checking that the user is still valid in your database or such;
        // for 3rd party IdPs, this may be tricky.
        return callback(null, {
            allowRefresh: true
        });
    };

    /**
     * Callback handler; this is the endpoint which is called when the OAuth2 provider
     * returns with a success or failure response.
     */
    private callbackHandler = (req, res, next) => {
        // Here we want to assemble the default profile and stuff.
        debug('callbackHandler()');
        // The authResponse is now in req.user (for this call), and we can pass that on as an authResponse
        // to continueAuthorizeFlow. Note the usage of "session: false", so that this data is NOT stored
        // automatically in the user session, which passport usually does by default.
        const authResponse = req.user;
        this.genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
    };

    // HELPER METHODS
    private createAuthResponse(profile: any): AuthResponse {
        debug(`createAuthResponse(${this.authMethodId})`);

        const defaultProfile = this.createDefaultProfile(profile);
        const defaultGroups = this.createDefaultGroups(profile);
        const customId = defaultProfile.sub;

        return {
            userId: null,
            customId: customId,
            defaultGroups: defaultGroups,
            defaultProfile: defaultProfile
        };
    }

    private createDefaultProfile(profile): OidcProfile {
        debug(`createDefaultProfile(${this.authMethodId}`);

        let customIdField = this.authMethodConfig.customIdField ? this.authMethodConfig.customIdField : 'upn';
        let nameField = this.authMethodConfig.nameField ? this.authMethodConfig.nameField : 'name';
        let firstNameField = this.authMethodConfig.firstNameField ? this.authMethodConfig.firstNameField : 'given_name';
        let lastNameField = this.authMethodConfig.lastNameField ? this.authMethodConfig.lastNameField : 'family_name';
        let emailField = this.authMethodConfig.emailField ? this.authMethodConfig.emailField : 'email';

        if (!profile[emailField])
            throw makeError('Profile must contain a valid email address.', 400);
        if (!profile[customIdField])
            throw makeError('Profile must contain a unique identifier field (custom ID field, UPN or similar)', 400);

        const customId = `${this.authMethodId}:${profile[customIdField]}`;
        const defaultProfile: OidcProfile = {
            sub: customId,
            email: profile[emailField],
            email_verified: !!this.authMethodConfig.trustUsers
        };
        const name = profile[nameField];
        const firstName = profile[firstNameField];
        const lastName = profile[lastNameField];

        if (name)
            defaultProfile.name = name;
        else
            defaultProfile.name = utils.makeFullName(lastName, firstName);
        if (firstName)
            defaultProfile.given_name = firstName;
        if (lastName)
            defaultProfile.family_name = lastName;

        // Iterate over the rest of the claims as well and return them
        for (let key in profile) {
            // Claim already present?
            if (defaultProfile.hasOwnProperty(key))
                continue;
            const value = profile[key];
            switch (typeof (value)) {
                case "string":
                case "number":
                    defaultProfile[key] = value;
                    break;
                default:
                    debug(`createAuthResponse(${this.authMethodId}: Skipping non-string/non-number profile key ${key}`);
                    break;
            }
        }

        return defaultProfile;
    }

    private createDefaultGroups(profile: any): string[] {
        debug(`createDefaultGroups(${this.authMethodId})`);
        if (!this.authMethodConfig.defaultGroups)
            return [];
        const groupField = this.authMethodConfig.groupField ? this.authMethodConfig.groupField : 'group';
        if (!profile[groupField])
            return [];
        const groups = profile[groupField];
        if (!Array.isArray(groups)) {
            warn(`createDefaultGroups(${this.authMethodId}): When creating profile, field ${groupField} is not a string array, defaulting to no groups.`);
            return [];
        }
        const defaultGroups = [];
        const groupMap = this.authMethodConfig.defaultGroups;
        for (let i = 0; i < groups.length; ++i) {
            const g = groups[i];
            if (groupMap[g]) {
                const wickedGroup = groupMap[g];
                debug(`Detected matching group ${g}: ${wickedGroup}`);
                defaultGroups.push(wickedGroup);
            }
        }
        debug(`createDefaultGroups(${this.authMethodId}): ${defaultGroups}`);
        return defaultGroups;
    }
}
