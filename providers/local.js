'use strict';

const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:local');
const qs = require('querystring');
const request = require('request');
const wicked = require('wicked-sdk');
const Router = require('express').Router;

const utils = require('../common/utils');
const utilsOAuth2 = require('../common/utils-oauth2');
const { failMessage, failError, failOAuth, makeError } = require('../common/utils-fail');
const profileStore = require('../common/profile-store');
const GenericOAuth2Router = require('../common/generic-router');

function LocalIdP(basePath, authMethodId, authMethodConfig/*, csrfProtection*/) {

    const genericFlow = new GenericOAuth2Router(basePath, authMethodId);
    this.basePath = basePath;
    this.authMethodId = authMethodId;
    this.config = authMethodConfig;

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
                uri: '/verify/:verificationId',
                handler: utils.createVerifyHandler(authMethodId)
            },
            {
                method: 'post',
                uri: '/verify',
                handler: utils.createVerifyEmailPostHandler(authMethodId)
            },
            {
                method: 'get',
                uri: '/forgotpassword',
                handler: utils.createForgotPasswordHandler(authMethodId)
            },
            {
                method: 'post',
                uri: '/forgotpassword',
                handler: utils.createForgotPasswordPostHandler(authMethodId)
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

        const email = req.body.email;
        const password = req.body.password;
        const password2 = req.body.password2;

        if (!password)
            return failMessage(400, 'Password cannot be empty', next);
        if (password !== password2)
            return failMessage(400, 'Passwords do not match', next);

        // Recaptcha?
        utils.verifyRecaptcha(req, (err) => {
            if (err)
                return failError(403, err, next);
            // Let's give it a shot; wicked can still intervene here...
            const emailValidated = authMethodConfig.trustUsers;
            const userCreateInfo = {
                email: email,
                password: password,
                groups: [],
                validated: emailValidated
            };
            debug(`signupPostHandler: Attempting to create user ${email}`);
            wicked.apiPost('/users', userCreateInfo, (err, userInfo) => {
                if (err)
                    return failError(500, err, next);

                debug(`signupPostHandler: Successfully created user ${email} with id ${userInfo.id}`);

                // Check whether we want to verify the email address or not
                utils.createVerificationRequest(authMethodConfig.trustUsers, authMethodId, userInfo, (err) => {
                    if (err)
                        return failError(500, err, next);

                    createAuthResponse(userInfo, (err, authResponse) => {
                        if (err)
                            return failError(500, err, next);
                        debug(`signupPostHandler: Successfully created an authResponse`);
                        debug(authResponse);

                        // We're practically logged in now, as the new user.
                        genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
                    });
                });
            });
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
        const viewModel = utils.createViewModel(req, authMethodId);
        res.render('login', viewModel);
    }

    function renderSignup(req, res) {
        debug('renderSignup()');
        res.render('signup', utils.createViewModel(req, authMethodId));
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

            const userShortInfo = userInfoList[0];
            // Load the user to get all information (e.g., groups and validated status)
            debug('userInfo: ' + JSON.stringify(userShortInfo));
            wicked.apiGet(`/users/${userShortInfo.id}`, (err, userInfo) => {
                if (err)
                    return callback(err);
                createAuthResponse(userInfo, (err, authResponse) => {
                    if (err)
                        return callback(err);
                    return callback(null, authResponse);
                });
            });
        });
    }

    function createDefaultProfile(userInfo) {
        debug('createDefaultProfile()');
        // For the local users, we don't have anything to put into the
        // default profile except the user ID and the email address.
        // For other IdPs, there may be other fields which can be prepopulated.
        const oidcProfile = {
            sub: userInfo.id,
            email: userInfo.email,
            email_verified: userInfo.validated,
        };
        debug(oidcProfile);
        return oidcProfile;
    }

    function createAuthResponse(userInfo, callback) {
        debug('createAuthResponse()');

        // TODO: Namespace handling
        return callback(null, {
            userId: userInfo.id,
            customId: null,
            defaultGroups: userInfo.groups,
            defaultProfile: createDefaultProfile(userInfo)
        });
    }

    genericFlow.initIdP(this);
}

module.exports = LocalIdP;
