'use strict';

const debug = require('debug')('portal-auth:local');
const qs = require('querystring');
const wicked = require('wicked-sdk');
const Router = require('express').Router;

const utils = require('../common/utils');
const utilsOAuth2 = require('../common/utils-oauth2');
const { failMessage, failError, failOAuth, makeError } = require('../common/utils-fail');
const profileStore = require('../common/profile-store');
const GenericOAuth2Router = require('../common/generic-router');

function LocalIdP(basePath, authMethodId/*, csrfProtection*/) {

    const genericFlow = new GenericOAuth2Router(basePath, authMethodId);
    this.basePath = basePath;
    this.authMethodId = authMethodId;

    this.getRouter = () => {
        return genericFlow.getRouter();
    };

    this.authorizeWithUi = (req, res, authRequest) => {
        // Do your thing...
        // Render a login mask...
        // Or redirect to a 3rd party IdP, like Google
        renderLogin(req, res, null);
    };

    this.endpoints = () => {
        return [
            {
                method: 'post',
                uri: '/login',
                handler: this.loginHandler
            }
        ];
    };

    this.loginHandler = (req, res, next) => {
        debug(`POST ${authMethodId}/login`);
        debug('loginHandler()');
        // When you're done with whatever (like verifying username and password,
        // or checking a callback from a 3rd party IdP), you must use the registered
        // generic flow implementation object (genericFlow from the constructor) to
        // pass back the same type of structure as in the authorizeByUserPass below.

        const username = req.body.username;
        const password = req.body.password;
        debug(`username: ${username}, password: ${password}`);

        loginUser(username, password, function (err, authResponse) {
            if (err) {
                debug(err);
                return renderLogin(req, res, 'Username or password invalid.');
            }

            genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
        });
    };

    this.authorizeByUserPass = (user, pass, callback) => {
        debug('authorizeByUserPass()');

        // loginUser already returns an authResponse, so we can just
        // pipe the callback to the upstream callback.
        return loginUser(user, pass, callback);
    };

    this.checkRefreshToken = (tokenInfo, callback) => {
        debug('checkRefreshToken()');
        // Decide whether it's okay to refresh this token or not, e.g.
        // by checking that the user is still valid in your database or such;
        // for 3rd party IdPs, this may be tricky.
        return callback(null, {
            allowRefresh: true
        });
    };

    function renderLogin(req, res, flashError) {
        debug('renderLogin()');
        res.render('login', {
            title: req.app.glob.title,
            portalUrl: wicked.getExternalPortalUrl(),
            baseUrl: req.app.get('base_path'),
            // csrfToken: req.csrfToken(),
            errorMessage: flashError,
            loginUrl: `${authMethodId}/login`
        });
    }

    function loginUser(username, password, callback) {
        debug('loginUser()');
        wicked.apiPost('login', {
            username: username,
            password: password
        }, function (err, userInfoList) {
            if (err)
                return callback(err);
            if (!Array.isArray(userInfoList))
                return callback(makeError('loginUser: Did not return expected format (array).', 500));
            if (userInfoList.length !== 1)
                return callback(makeError(`loginUser: /login did not return user (array length ${userInfoList.length})`, 500));
            debug('loginUser: /login successful');
            // TODO: Real profile, for now userInfo from wicked...
            // TBD: Eh?
            const userInfo = userInfoList[0];
            debug('userInfo: ' + JSON.stringify(userInfo));

            createAuthResponse(userInfo, (err, authResponse) => {
                if (err)
                    return callback(err);
                return callback(null, authResponse);
            });

        });
    }

    function createAuthResponse(userInfo, callback) {
        debug('createAuthResponse()');

        utilsOAuth2.wickedUserInfoToOidcProfile(userInfo, (err, oidcProfile) => {
            if (err)
                return callback(err);
            return callback(null, {
                userId: userInfo.id,
                customId: null,
                defaultGroups: userInfo.groups,
                defaultProfile: oidcProfile // Meh
            });
        });
    }

    genericFlow.initIdP(this);
}

module.exports = LocalIdP;
