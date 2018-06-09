'use strict';

const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:local');
const wicked = require('wicked-sdk');

const GenericOAuth2Router = require('../common/generic-router');

function DummyIdP(basePath, authMethodId, authMethodConfig, options) {

    const genericFlow = new GenericOAuth2Router(basePath, authMethodId);

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
        // When you're done with whatever (like verifying username and password,
        // or checking a callback from a 3rd party IdP), you must use the registered
        // generic flow implementation object (genericFlow from the constructor) to
        // pass back the same type of structure as in the authorizeByUserPass below.

        //const apiId = req.params.apiId;
        debug(`POST ${authMethodId}/login`);

        const authResponse = getDummyAuthResponse();
        genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
    };

    this.authorizeByUserPass = (user, pass, callback) => {
        debug('authorizeByUserPass()');

        return callback(null, getDummyAuthResponse());
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

    function getDummyAuthResponse() {
        return {
            customId: 'dummy:1234567890',
            defaultGroups: [],
            defaultProfile: {
                email: 'dummy@hello.com',
                email_verified: false,
                given_name: 'Dummy',
                family_name: 'Userson'
            }
        };
    }

    function renderLogin(req, res, flashError) {
        debug('renderLogin()');
        res.render('dummy', {
            title: req.app.glob.title,
            portalUrl: wicked.getExternalPortalUrl(),
            baseUrl: req.app.get('base_path'),
            errorMessage: flashError,
            loginUrl: `${authMethodId}/login`
        });
    }

    genericFlow.initIdP(this);
}

module.exports = DummyIdP;
