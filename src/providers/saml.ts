'use strict';

import { GenericOAuth2Router } from '../common/generic-router';
import { AuthRequest, EndpointDefinition, AuthResponseCallback, CheckRefreshCallback, AuthResponse, IdentityProvider, IdpOptions, SamlIdpConfig } from '../common/types';
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:idp');
const Router = require('express').Router;
const saml2 = require('saml2-js');

import { utils } from '../common/utils';
import { failMessage, failError, failOAuth, makeError } from '../common/utils-fail';

/**
 * SAML OAuth2 Wrapper implementation
 */
export class SamlIdP implements IdentityProvider {

    private genericFlow: GenericOAuth2Router;
    private basePath: string;
    private authMethodId: string;
    private options: IdpOptions;
    private authMethodConfig: SamlIdpConfig;

    private serviceProvider: any;
    private identityProvider: any;

    constructor(basePath: string, authMethodId: string, authMethodConfig: any, options: IdpOptions) {
        debug(`constructor(${basePath}, ${authMethodId},...)`);
        this.genericFlow = new GenericOAuth2Router(basePath, authMethodId);

        this.basePath = basePath;
        this.authMethodId = authMethodId;
        this.authMethodConfig = authMethodConfig;

        if (!authMethodConfig.spOptions)
            throw new Error(`SAML Auth Method ${authMethodId}: config does not contain an "spOptions" property.`);
        if (!authMethodConfig.idpOptions)
            throw new Error(`SAML Auth Method ${authMethodId}: config does not contain an "idpOptions" property.`);

        // Assemble the SAML endpoints
        const assertUrl = `${options.externalUrlBase}/${authMethodId}/assert`;
        info(`SAML Authentication: Assert URL: ${assertUrl}`);
        const entityUrl = `${options.externalUrlBase}/${authMethodId}/metadata.xml`;
        info(`SAML Authentication: Metadata URL: ${entityUrl}`);

        this.authMethodConfig.spOptions.assert_endpoint = assertUrl;
        this.authMethodConfig.spOptions.entity_id = entityUrl;

        this.serviceProvider = new saml2.ServiceProvider(authMethodConfig.spOptions);
        this.identityProvider = new saml2.IdentityProvider(authMethodConfig.idpOptions);

        this.genericFlow.initIdP(this);
    }

    public getType() {
        return "idp";
    }

    public getRouter() {
        return this.genericFlow.getRouter();
    }

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
        this.serviceProvider.create_login_request_url(this.identityProvider, {}, function (err, loginUrl, requestId) {
            if (err)
                return failError(500, err, next);
            // What shall we do with the request ID...
            res.redirect(loginUrl);
        });
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
                uri: '/metadata.xml',
                handler: this.metadataHandler
            },
            {
                method: 'post',
                uri: '/assert',
                handler: this.assertHandler
            }
        ];
    };

    private samlMetadata: string = null;
    private metadataHandler = (req, res, next) => {
        res.type('application/xml');
        if (!this.samlMetadata) {
            this.samlMetadata = this.serviceProvider.create_metadata();
        }
        res.send(this.samlMetadata);
    }

    private assertHandler = (req, res, next) => {
        return next(new Error('Not implemented'));
    }

    /**
     * Verify username and password and return the data on the user, like
     * when authorizing via some 3rd party. If this identity provider cannot
     * authenticate via username and password, an error will be returned.
     * 
     * @param {*} user Username
     * @param {*} pass Password
     * @param {*} callback Callback method, `function(err, authenticationData)`
     */
    public authorizeByUserPass(user: string, pass: string, callback: AuthResponseCallback) {
        // Verify username and password, if possible.
        // Otherwise (for IdPs where this is not possible), return
        // an error with a reason. Use utils.failOAuth to create
        // an error which will be returned as JSON by the framework.

        // Here, we assume user and pass are OK.
        return callback(null, this.getAuthResponse());
    };

    public checkRefreshToken(tokenInfo, callback: CheckRefreshCallback) {
        // Decide whether it's okay to refresh this token or not, e.g.
        // by checking that the user is still valid in your database or such;
        // for 3rd party IdPs, this may be tricky.
        return callback(null, {
            allowRefresh: true
        });
    };

    // Sample implementation
    private getAuthResponse(): AuthResponse {
        // This is obviously just dummy code showing how the response
        // must look like to play nice with the 
        return {
            // The wicked database user ID, in case we already know this
            // user (this only applies for local login with username and
            // password)
            userId: null,
            // A string giving a unique user id for this IdP, usually with
            // a prefix which corresponds with the auth method name this
            // IdP is used for. This is used as a unique custom ID for the
            // wicked user in the local database.
            customId: 'idp:<user id in idp>',
            // In case you have a predefined mapping to wicked user groups,
            // E.g. from LDAP or AD groups, pass them in as strings here.
            defaultGroups: [],
            // Default OIDC profile
            defaultProfile: {
                // This shouldn't be filled; will be overridden anyway
                sub: null,
                email: "default@user.org",
                // Specify whether the user's email address is pre-verified
                // or not. I.e., whether you trust the email address of
                // the IdP or not.
                email_verified: true,
                given_name: "Default",
                family_name: "User"
                // If you want to pass in more OIDC profile parameters,
                // feel free to do so. See:
                // http://openid.net/specs/openid-connect-core-1_0.html#Claims
            }
        };
    };
}
