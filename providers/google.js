'use strict';

const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:github');
const Router = require('express').Router;

const utils = require('../common/utils');
const { failMessage, failError, failOAuth, makeError } = require('../common/utils-fail');

const GenericOAuth2Router = require('../common/generic-router');

const passport = require('passport');

const GoogleStrategy = require('passport-google-oauth20').Strategy;

/**
 * Google IdP implementation.
 */
function GoogleIdP(basePath, authMethodId, authMethodConfig, options) {

    const genericFlow = new GenericOAuth2Router(basePath, authMethodId);
    const instance = this;

    // debug(authMethodConfig);
    // Verify configuration
    if (!authMethodConfig.clientId)
        throw new Error(`Google auth method "${authMethodId}": In auth method configuration, property "config", the property "clientId" is missing.`);
    if (!authMethodConfig.clientSecret)
        throw new Error(`Google auth method "${authMethodId}": In auth-server configuration, property "config", the property "clientSecret" is missing.`);

    // Assemble the callback URL
    const callbackUrl = `${options.externalUrlBase}/${authMethodId}/callback`;
    info(`Google Authentication: Expected callback URL: ${callbackUrl}`);

    const authenticateSettings = {
        session: false,
        scope: ['profile', 'email'],
        failureRedirect: `${options.basePath}/failure`
    };

    const verifyProfile = (accessToken, refreshToken, profile, done) => {
        debug('Google Authentication succeeded.');
        // We'll always accept Google Identities, no matter what.
        createAuthResponse(profile, function (err, authResponse) {
            if (err) {
                error('Google Authentication: normalizeProfile failed.');
                error(err);
                return done(err);
            }
            debug('Google normalized user profile:');
            debug(authResponse);
            done(null, authResponse);
        });
    };

    // Configure passport
    passport.use(authMethodId, new GoogleStrategy({
        clientID: authMethodConfig.clientId,
        clientSecret: authMethodConfig.clientSecret,
        callbackURL: callbackUrl
    }, verifyProfile));

    const authenticateWithGoogle = passport.authenticate(authMethodId, authenticateSettings);
    const authenticateCallback = passport.authenticate(authMethodId, authenticateSettings);

    // google.get('/api/:apiId', utils.verifyClientAndAuthenticate('google', authenticateWithGoogle));
    // google.get('/callback', authenticateCallback, utils.authorizeAndRedirect('google', google.authServerName));

    const createAuthResponse = (profile, callback) => {
        const email = getEmail(profile);
        const email_verified = !!email;

        const customId = `${authMethodId}:${profile.id}`;
        const defaultProfile = {
            username: utils.makeUsername(profile.displayName, profile.username),
            preferred_username: utils.makeUsername(profile.displayName, profile.username),
            name: profile.displayName,
            given_name: profile.name.givenName,
            family_name: profile.name.familyName,
            email: email,
            email_verified: email_verified
        };
        const authResponse = {
            userId: null, // will be filled by genericFlow
            customId: customId,
            defaultGroups: [],
            defaultProfile: defaultProfile
        };
        callback(null, authResponse);
    };

    const getEmail = (profile) => {
        debug('getEmail()');
        if (!profile.emails)
            return null;
        if (profile.emails.length <= 0)
            return null;
        return profile.emails[0].value;
    };

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
        // Redirect to the Google login page
        return authenticateWithGoogle(req, res);
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
        // For Google, this is not possible, so we will just return an
        // error message.
        return failOAuth(400, 'unsupported_grant_type', 'Google does not support authorizing headless with username and password', callback);
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

module.exports = GoogleIdP;
