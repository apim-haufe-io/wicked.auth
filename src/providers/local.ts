'use strict';

import { GenericOAuth2Router } from '../common/generic-router';
import { AuthRequest, AuthResponse, IdentityProvider, EndpointDefinition, IdpOptions, LocalIdpConfig, AuthResponseCallback, CheckRefreshCallback, OidcProfile } from '../common/types';
import { WickedUserInfo } from '../common/wicked-types';
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:local');
const wicked = require('wicked-sdk');
const Router = require('express').Router;

import { utils } from '../common/utils';
import { failMessage, failError, failOAuth, makeError } from '../common/utils-fail';

export class LocalIdP implements IdentityProvider {

    private genericFlow: GenericOAuth2Router;
    private basePath: string;
    private authMethodId: string;
    private authMethodConfig: LocalIdpConfig;
    private options: IdpOptions;

    constructor(basePath: string, authMethodId: string, authMethodConfig: LocalIdpConfig, options: IdpOptions) {
        debug(`constructor(${basePath}, ${authMethodId}, ...)`);
        this.genericFlow = new GenericOAuth2Router(basePath, authMethodId);
        this.authMethodId = authMethodId;
        this.authMethodConfig = authMethodConfig;
        this.options = options;

        this.genericFlow.initIdP(this);
    }

    public getType(): string {
        return "local";
    }

    public getRouter() {
        return this.genericFlow.getRouter();
    }

    public authorizeWithUi(req, res, authRequest: AuthRequest) {
        // Render a login mask...
        this.renderLogin(req, res, null);
    }

    public authorizeByUserPass(user, pass, callback: AuthResponseCallback) {
        debug('authorizeByUserPass()');

        // loginUser already returns an authResponse, so we can just
        // pipe the callback to the upstream callback.
        return this.loginUser(user, pass, callback);
    }

    public checkRefreshToken(tokenInfo, callback: CheckRefreshCallback) {
        debug('checkRefreshToken()');
        // Decide whether it's okay to refresh this token or not, e.g.
        // by checking that the user is still valid in your database or such;
        // for 3rd party IdPs, this may be tricky.
        return callback(null, {
            allowRefresh: true
        });
    }

    public endpoints(): EndpointDefinition[] {
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
                uri: '/forgotpassword',
                handler: this.genericFlow.createForgotPasswordHandler(this.authMethodId)
            },
            {
                method: 'post',
                uri: '/forgotpassword',
                handler: this.genericFlow.createForgotPasswordPostHandler(this.authMethodId)
            }
        ];
    }

    private loginHandler = (req, res, next): void => {
        debug(`POST ${this.authMethodId}/login`);
        debug('loginHandler()');
        // When you're done with whatever (like verifying username and password,
        // or checking a callback from a 3rd party IdP), you must use the registered
        // generic flow implementation object (genericFlow from the constructor) to
        // pass back the same type of structure as in the authorizeByUserPass below.
        const body = req.body;
        const csrfToken = body._csrf;
        const expectedCsrfToken = utils.getAndDeleteCsrfToken(req);
        const instance = this;

        if (!csrfToken || csrfToken !== expectedCsrfToken)
            return this.renderLogin(req, res, 'Suspected login forging detected (CSRF protection).');

        const username = req.body.username;
        const password = req.body.password;
        debug(`username: ${username}, password: ${password}`);

        this.loginUser(username, password, (err, authResponse) => {
            if (err) {
                debug(err);
                return instance.renderLogin(req, res, 'Username or password invalid.');
            }

            instance.genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
        });
    };

    private signupHandler = (req, res, next) => {
        debug(`GET ${this.authMethodId}/signup`);
        debug('signupHandler()');
        this.renderSignup(req, res, '');
    };

    private signupPostHandler = (req, res, next) => {
        debug(`POST ${this.authMethodId}/signup`);
        debug('signupPostHandler()');

        const body = req.body;
        const csrfToken = body._csrf;
        const expectedCsrfToken = utils.getAndDeleteCsrfToken(req);
        const instance = this;

        if (!csrfToken || expectedCsrfToken !== csrfToken)
            return setTimeout(this.renderSignup, 500, req, res, 'CSRF validation failed, please try again.');

        const email = body.email;
        const password = body.password;
        const password2 = body.password2;

        if (!password)
            return failMessage(400, 'Password cannot be empty', next);
        if (password !== password2)
            return failMessage(400, 'Passwords do not match', next);

        // Recaptcha?
        utils.verifyRecaptcha(req, (err) => {
            if (err)
                return failError(403, err, next);
            // Let's give it a shot; wicked can still intervene here...
            const emailValidated = this.authMethodConfig.trustUsers;
            const userCreateInfo = {
                email: email,
                password: password,
                groups: [],
                validated: emailValidated
            } as WickedUserInfo;
            debug(`signupPostHandler: Attempting to create user ${email}`);
            wicked.apiPost('/users', userCreateInfo, (err, userInfo: WickedUserInfo) => {
                if (err)
                    return failError(500, err, next);

                debug(`signupPostHandler: Successfully created user ${email} with id ${userInfo.id}`);

                // Check whether we want to verify the email address or not
                utils.createVerificationRequest(this.authMethodConfig.trustUsers, this.authMethodId, userInfo.email, (err) => {
                    if (err)
                        return failError(500, err, next);

                    const authResponse = instance.createAuthResponse(userInfo);
                    debug(`signupPostHandler: Successfully created an authResponse`);
                    debug(authResponse);

                    // We're practically logged in now, as the new user.
                    instance.genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
                });
            });
        });
    };

    private renderLogin(req, res, flashMessage: string) {
        debug('renderLogin()');
        const viewModel = utils.createViewModel(req, this.authMethodId);
        viewModel.errorMessage = flashMessage;
        res.render('login', viewModel);
    }

    private renderSignup(req, res, flashMessage: string) {
        debug('renderSignup()');
        const viewModel = utils.createViewModel(req, this.authMethodId);
        viewModel.errorMessage = flashMessage;
        res.render('signup', viewModel);
    }

    private loginUser(username: string, password: string, callback: AuthResponseCallback) {
        debug('loginUser()');
        const instance = this;
        wicked.apiPost('login', {
            username: username,
            password: password
        }, function (err, userInfoList: WickedUserInfo[]) {
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
            wicked.apiGet(`/users/${userShortInfo.id}`, (err, userInfo: WickedUserInfo) => {
                if (err)
                    return callback(err);
                const authResponse = instance.createAuthResponse(userInfo);
                return callback(null, authResponse);
            });
        });
    }

    private createDefaultProfile(userInfo: WickedUserInfo): OidcProfile {
        debug('createDefaultProfile()');
        // For the local users, we don't have anything to put into the
        // default profile except the user ID and the email address.
        // For other IdPs, there may be other fields which can be prepopulated.
        const oidcProfile = {
            sub: userInfo.id,
            email: userInfo.email,
            email_verified: userInfo.validated,
        } as OidcProfile;
        debug(oidcProfile);
        return oidcProfile;
    }

    private createAuthResponse(userInfo: WickedUserInfo): AuthResponse {
        debug('createAuthResponse()');

        // TODO: Namespace handling
        return {
            userId: userInfo.id,
            defaultGroups: userInfo.groups,
            defaultProfile: this.createDefaultProfile(userInfo)
        };
    }
}
