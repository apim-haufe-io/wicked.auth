'use strict';

const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:twitter');
const Router = require('express').Router;

const utils = require('../common/utils');
const { failMessage, failError, failOAuth, makeError } = require('../common/utils-fail');

const GenericOAuth2Router = require('../common/generic-router');

const request = require('request');
const passport = require('passport');
const Twitter = require('twitter');

const TwitterStrategy = require('passport-twitter');

/**
 * Twitter IdP implementation.
 */
function TwitterIdP(basePath, authMethodId, authMethodConfig, options) {

    const genericFlow = new GenericOAuth2Router(basePath, authMethodId);
    const instance = this;

    // debug(authMethodConfig);
    // Verify configuration
    if (!authMethodConfig.consumerKey)
        throw new Error(`Twitter auth method "${authMethodId}": In auth method configuration, property "config", the property "consumerKey" is missing.`);
    if (!authMethodConfig.consumerSecret)
        throw new Error(`Twitter auth method "${authMethodId}": In auth-server configuration, property "config", the property "consumerSecret" is missing.`);

    // Assemble the callback URL
    const callbackUrl = `${options.externalUrlBase}/${authMethodId}/callback`;
    info(`Twitter Authentication: Expected callback URL: ${callbackUrl}`);

    // ========================
    // HELPER METHODS
    // ========================

    const verifyProfile = (token, tokenSecret, profile, done) => {
        debug('Twitter Authentication succeeded.');
        createAuthResponse(profile, token, tokenSecret, function (err, authResponse) {
            if (err) {
                error('createAuthResponse failed.');
                error(err);
                return done(err);
            }
            debug('Twitter authResponse:');
            debug(authResponse);
            done(null, authResponse);
        });
    };


    const createAuthResponse = (profile, token, tokenSecret, callback) => {
        debug('normalizeProfile()');

        const nameGuess = utils.splitName(profile.displayName, profile.username);
        const email = null; // We don't get email addresses from Twitter as a default
        const email_verified = false;

        const customId = `${authMethodId}:${profile.id}`;
        debug(`Twitter token: ${token}`);
        debug(`Twitter tokenSecret: ${tokenSecret}`);
        //debug('Twitter raw profile:');
        //debug(profile);

        const defaultProfile = {
            username: utils.makeUsername(nameGuess.fullName, profile.username),
            preferred_username: utils.makeUsername(nameGuess.fullName, profile.username),
            name: nameGuess.fullName,
            given_name: nameGuess.firstName,
            family_name: nameGuess.lastName,
            email: email,
            email_verified: email_verified
        };

        // To read the email address, we need the twitter client. Twitter requires
        // signing all requests, and thus it's easier to use a library for that rather
        // than trying to roll our own signing...
        const twitterClient = new Twitter({
            consumer_key: authMethodConfig.consumerKey,
            consumer_secret: authMethodConfig.consumerSecret,
            access_token_key: token,
            access_token_secret: tokenSecret
        });

        // See https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials
        const twitterParams = { include_email: true };
        debug('Attempting to verify Twitter credentials...');
        twitterClient.get('account/verify_credentials', twitterParams, (err, extendedProfile, response) => {
            if (err)
                return callback(err);
            debug('Successfully verified Twitter credentials, here are the results:');
            debug(extendedProfile);

            const jsonBody = utils.getJson(extendedProfile);

            if (jsonBody.email) {
                // If we have an email address, Twitter assures it's already verified.
                defaultProfile.email = jsonBody.email;
                defaultProfile.email_verified = true;
            }

            const authResponse = {
                userId: null,
                customId: customId,
                defaultGroups: [],
                defaultProfile: defaultProfile
            };
            debug('Twitter authResponse:');
            debug(authResponse);

            callback(null, authResponse);
        });
    };

    // ========================
    // PASSPORT INITIALIZATION
    // ========================

    // Use the authMethodId as passport "name"; which is subsequently used below
    // to identify the strategy to use for a specific end point (see passport.authenticate)

    const authenticateSettings = {
        session: false,
        failureRedirect: '/auth-server/failure'
    };

    passport.use(new TwitterStrategy({
        consumerKey: authMethodConfig.consumerKey,
        consumerSecret: authMethodConfig.consumerSecret,
        callbackURL: callbackUrl
    }, verifyProfile));

    const authenticateWithTwitter = passport.authenticate(authMethodId, authenticateSettings);
    const authenticateCallback = passport.authenticate(authMethodId, authenticateSettings);

    // We will be called back (hopefully) on this end point via the emailMissingPostHandler (in utils.js)
    const continueAuthenticate = (req, res, next, email) => {
        debug(`continueAuthenticate(${authMethodId})`);

        const session = req.session[authMethodId];

        if (!session ||
            !session.tmpAuthResponse) {
            return failMessage(500, 'Invalid state: Was expecting a temporary auth response.', next);
        }
        const authResponse = session.tmpAuthResponse;
        delete session.tmpAuthResponse;

        authResponse.defaultProfile.email = email;
        authResponse.defaultProfile.email_verified = false;

        return genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
    };

    // The email missing handler will be called if we do not get an email address back from
    // Twitter, which may happen. It may be that we still already have the email address, in case
    // the user already exists. This is checked in the createEmailMissingHandler.
    const emailMissingHandler = genericFlow.createEmailMissingHandler(authMethodId, continueAuthenticate);

    /**
     * Twitter callback handler; this is the endpoint which is called when Twitter
     * returns with a success or failure response.
     */
    this.callbackHandler = (req, res, next) => {
        // Here we want to assemble the default profile and stuff.
        debug('callbackHandler()');
        // The authResponse is now in req.user (for this call), and we can pass that on as an authResponse
        // to continueAuthorizeFlow. Note the usage of "session: false", so that this data is NOT stored
        // automatically in the user session, which passport usually does by default.
        const authResponse = req.user;

        // Now we have to check whether we received an email adress from Twitter; if not, we need to ask
        // the user for one.
        if (authResponse.defaultProfile &&
            authResponse.defaultProfile.email) {
            // Yes, all is good, we can go back to the generic router
            return genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
        }

        // No email from Twitter, let's ask for one, but we must store the temporary authResponse for later
        // usage, in the session. It may be that emailMissingHandler is able to retrieve the email address
        // from wicked, if the user is already registered. Otherwise the user will be asked.
        req.session[authMethodId].tmpAuthResponse = authResponse;

        return emailMissingHandler(req, res, next, authResponse.customId);
    };

    this.getRouter = () => {
        return genericFlow.getRouter();
    };

    this.authorizeWithUi = (req, res, authRequest) => {
        // Do your thing...
        // Redirect to the Twitter login page
        return authenticateWithTwitter(req, res);
    };

    this.endpoints = () => {
        return [
            {
                method: 'get',
                uri: '/callback',
                middleware: authenticateCallback,
                handler: instance.callbackHandler
            },
            {
                method: 'post',
                uri: '/emailmissing',
                handler: genericFlow.createEmailMissingPostHandler(authMethodId, continueAuthenticate)
            }
        ];
    };

    this.authorizeByUserPass = (user, pass, callback) => {
        // Verify username and password, if possible.
        // For Twitter, this is not possible, so we will just return an
        // error message.
        return failOAuth(400, 'unsupported_grant_type', 'Twitter does not support authorizing headless with username and password', callback);
    };

    this.checkRefreshToken = (tokenInfo, callback) => {
        // Decide whether it's okay to refresh this token or not, e.g.
        // by checking that the user is still valid in your database or such;
        // for 3rd party IdPs, this may be tricky. For Twitter, we will just allow it.
        return callback(null, {
            allowRefresh: true
        });
    };

    genericFlow.initIdP(this);
}

module.exports = TwitterIdP;
