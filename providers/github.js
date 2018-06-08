'use strict';

const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:github');
const Router = require('express').Router;

const utils = require('../common/utils');
const { failMessage, failError, failOAuth, makeError } = require('../common/utils-fail');

const GenericOAuth2Router = require('../common/generic-router');

const request = require('request');
const passport = require('passport');
const GithubStrategy = require('passport-github2');

/**
 * Github IdP implementation.
 */
function GithubIdP(basePath, authMethodId, authMethodConfig, options) {

    const genericFlow = new GenericOAuth2Router(basePath, authMethodId);
    const instance = this;

    // debug(authMethodConfig);
    // Verify configuration
    if (!authMethodConfig.clientId)
        throw new Error(`Github auth method "${authMethodId}": In auth method configuration, property "config", the property "clientId" is missing.`);
    if (!authMethodConfig.clientSecret)
        throw new Error(`Github auth method "${authMethodId}": In auth-server configuration, property "config", the property "clientSecret" is missing.`);

    // Assemble the callback URL
    const callbackUrl = `${options.externalUrlBase}/${authMethodId}/callback`;
    info(`Github Authentication: Expected callback URL: ${callbackUrl}`);

    // ========================
    // HELPER METHODS
    // ========================

    const createAuthResponse = (profile, accessToken, callback) => {
        debug('createAuthResponse()');
        debug(profile);
        // Get the email addresses; they are not included in the OAuth profile directly.
        request.get({
            url: 'https://api.github.com/user/emails',
            headers: {
                'User-Agent': 'wicked Auth Server',
                'Authorization': 'Bearer ' + accessToken,
                'Accept': 'application/json'
            }
        }, (err, apiResponse, apiBody) => {
            if (err)
                return callback(err);
            debug('Github Email retrieved.');

            const nameGuess = utils.splitName(profile.displayName, profile.username);
            const email = getEmailData(utils.getJson(apiBody));
            debug(email);

            const customId = `${authMethodId}:${profile.id}`;

            const defaultProfile = {
                username: utils.makeUsername(nameGuess.fullName, profile.username),
                preferred_username: utils.makeUsername(nameGuess.fullName, profile.username),
                name: nameGuess.fullName,
                given_name: nameGuess.firstName,
                family_name: nameGuess.lastName,
                email: email.email,
                email_verified: email.verified,
            };

            const authResponse = {
                userId: null, // Not yet known, which is fine
                customId: customId,
                defaultGroups: [],
                defaultProfile: defaultProfile
            };
            debug(`Assembled auth response for ${customId}:`);
            debug(authResponse);

            return callback(null, authResponse);
        });
    };

    const getEmailData = (emailResponse) => {
        debug('getEmailData()');
        debug(emailResponse);
        const email = {
            email: null,
            verified: false
        };
        const primaryEmail = emailResponse.find(function (emailItem) { return emailItem.primary; });
        if (primaryEmail) {
            email.email = primaryEmail.email;
            email.verified = primaryEmail.verified;
            return email;
        }
        const validatedEmail = emailResponse.find(function (emailItem) { return emailItem.verified; });
        if (validatedEmail) {
            email.email = validatedEmail.email;
            email.verified = validatedEmail.verified;
            return email;
        }
        if (emailResponse.length > 0) {
            const firstEmail = emailResponse[0];
            email.email = firstEmail.email;
            email.verified = firstEmail.verified;
            return email;
        }

        return email;
    };

    const verifyProfile = function (accessToken, refreshToken, profile, done) {
        debug('verifyProfile()');
        createAuthResponse(profile, accessToken, function (err, authResponse) {
            debug('callback normalizeProfile()');
            if (err) {
                error('normalizeProfile failed.');
                error(err);
                return done(err);
            }
            debug('Github authResponse:');
            debug(authResponse);
            done(null, authResponse);
        });
    };

    // ========================
    // PASSPORT INITIALIZATION
    // ========================
    
    // Use the authMethodId as passport "name"; which is subsequently used below
    // to identify the strategy to use for a specific end point (see passport.authenticate)
    passport.use(authMethodId, new GithubStrategy({
        clientID: authMethodConfig.clientId,
        clientSecret: authMethodConfig.clientSecret,
        callbackURL: callbackUrl
    }, verifyProfile));

    // We won't use the passport session handling; no need for that.
    const authenticateSettings = {
        session: false,
        scope: ['user:email'],
        failureRedirect: `${options.basePath}/failure`
    };

    const authenticateWithGithub = passport.authenticate(authMethodId, authenticateSettings);
    const authenticateCallback = passport.authenticate(authMethodId, authenticateSettings);

    /**
     * Github callback handler; this is the endpoint which is called when Github
     * returns with a success or failure response.
     */
    instance.callbackHandler = (req, res, next) => {
        // Here we want to assemble the default profile and stuff.
        debug('callbackHandler()');
        // The authResponse is now in req.user (for this call), and we can pass that on as an authResponse
        // to continueAuthorizeFlow. Note the usage of "session: false", so that this data is NOT stored
        // automatically in the user session, which passport usually does by default.
        const authResponse = req.user;
        genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
    };

    instance.getRouter = () => {
        return genericFlow.getRouter();
    };

    instance.authorizeWithUi = (req, res, authRequest) => {
        // Do your thing...
        // Redirect to the Github login page
        return authenticateWithGithub(req, res);
    };

    instance.endpoints = () => {
        return [
            {
                method: 'get',
                uri: '/callback',
                middleware: authenticateCallback,
                handler: instance.callbackHandler
            }
        ];
    };

    instance.authorizeByUserPass = (user, pass, callback) => {
        // Verify username and password, if possible.
        // For Github, this is not possible, so we will just return an
        // error message.
        return failOAuth(400, 'unsupported_grant_type', 'Github does not support authorizing headless with username and password', callback);
    };

    instance.checkRefreshToken = (tokenInfo, callback) => {
        // Decide whether it's okay to refresh this token or not, e.g.
        // by checking that the user is still valid in your database or such;
        // for 3rd party IdPs, this may be tricky. For Github, we will just allow it.
        return callback(null, {
            allowRefresh: true
        });
    };

    genericFlow.initIdP(instance);
}

module.exports = GithubIdP;
