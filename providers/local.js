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
            },
            {
                method: 'get',
                uri: '/signup',
                handler: this.signupHandler
            },
            {
                method: 'post',
                uri: '/signup',
                handler: this.signupPostHandler
            },
            {
                method: 'get',
                uri: '/register',
                handler: this.registerHandler
            },
            {
                method: 'post',
                uri: '/register',
                handler: this.registerPostHandler
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

    this.signupHandler = (req, res, next) => {
        debug(`GET ${authMethodId}/signup`);
        debug('signupHandler()');
        renderSignup(req, res);
    };

    this.signupPostHandler = (req, res, next) => {
        debug(`POST ${authMethodId}/signup`);
        debug('signupPostHandler()');

        // TODO
        // renderLogin(req, res);
    };

    this.registerHandler = (req, res, next) => {
        debug(`GET ${authMethodId}/register`);
        debug('registerHandler()');
        if (!req.session || 
            !req.session[authMethodId] || 
            !req.session[authMethodId].authResponse || 
            !req.session[authMethodId].authResponse.profile) {
            return failMessage(401, 'You are not logged in.', next);
        }
        renderRegister(req, res);
    };

    this.registerPostHandler = (req, res, next) => {
        debug(`POST ${authMethodId}/register`);
        debug('registerPostHandler()');

        // TODO
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

    function makeViewModel(req) {
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

    function renderLogin(req, res, flashError) {
        debug('renderLogin()');
        const viewModel = makeViewModel(req);
        res.render('login', viewModel);
    }

    function renderSignup(req, res) {
        debug('renderSignup()');
        res.render('signup', makeViewModel(req));
    }

    function renderRegister(req, res) {
        debug('renderRegister()');
        const viewModel = makeViewModel(req);
        const userProfile = req.session[authMethodId].authResponse.profile;
        debug(userProfile);
        res.render('register', makeViewModel(req));
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
