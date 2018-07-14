'use strict';

import { GenericOAuth2Router } from '../common/generic-router';
import { AuthRequest, EndpointDefinition, AuthResponse, IdentityProvider, IdpOptions, SamlIdpConfig, OidcProfile, CheckRefreshDecision } from '../common/types';
import { Callback } from 'wicked-sdk';
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:idp');
const Router = require('express').Router;
const saml2 = require('saml2-js');
const mustache = require('mustache');

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
        if (!authMethodConfig.profile)
            throw new Error(`SAML Auth Method ${authMethodId}: config does not contain a "profile" property.`);
        if (!authMethodConfig.profile.sub || !authMethodConfig.profile.email)
            throw new Error(`SAML Auth Method ${authMethodId}: config of profile must contain both "sub" and "email" mappings.`);

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
        return "saml";
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
            // Remember the request ID
            authRequest.requestId = requestId;
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
        return [
            {
                method: 'get',
                uri: '/metadata.xml',
                handler: this.createMetadataHandler()
            },
            {
                method: 'post',
                uri: '/assert',
                handler: this.createAssertHandler()
            }
        ];
    };

    private samlMetadata: string = null;
    private createMetadataHandler() {
        const instance = this;
        return function (req, res, next) {
            res.type('application/xml');
            if (!instance.samlMetadata) {
                instance.samlMetadata = instance.serviceProvider.create_metadata();
            }
            res.send(instance.samlMetadata);
        }
    }

    private createAssertHandler() {
        const instance = this;
        return function (req, res, next) {
            debug(`assertHandler()`);
            const authRequest = utils.getAuthRequest(req, instance.authMethodId);
            const requestId = authRequest.requestId;
            if (!requestId)
                return failMessage(400, 'Invalid state for SAML Assert: Request ID is not present', next);
            instance.assert(req, requestId, function (err, samlResponse) {
                if (err)
                    return failError(500, err, next);
                debug(samlResponse);
                instance.createAuthResponse(samlResponse, function (err, authResponse) {
                    if (err)
                        return next(err);
                    return instance.genericFlow.continueAuthorizeFlow(req, res, next, authResponse);
                });
            });
        }
    }

    private createAuthResponse(samlResponse, callback: Callback<AuthResponse>): void {
        debug(`createAuthResponse()`);
        const defaultProfile = this.buildProfile(samlResponse);
        if (!defaultProfile.sub)
            return callback(makeError('SAML Response did not contain a suitable ID (claim "sub" is missing/faulty in configuration?)', 400));
        // Map to custom ID
        const customId = `${this.authMethodId}:${defaultProfile.sub}`;
        defaultProfile.sub = customId;
        debug(defaultProfile);
        const authResponse: AuthResponse = {
            userId: null,
            customId: customId,
            defaultProfile: defaultProfile,
            defaultGroups: []
        }
        return callback(null, authResponse);
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
    public authorizeByUserPass(user: string, pass: string, callback: Callback<AuthResponse>) {
        debug('authorizeByUserPass()');
        return failOAuth(400, 'unsupported_grant_type', 'SAML does not support authorizing headless with username and password', callback);
    };

    public checkRefreshToken(tokenInfo, callback: Callback<CheckRefreshDecision>) {
        // Decide whether it's okay to refresh this token or not, e.g.
        // by checking that the user is still valid in your database or such;
        // for 3rd party IdPs, this may be tricky.
        return callback(null, {
            allowRefresh: true
        });
    };

    private getLogoutResponseUrl(inResponseTo, relayState, callback) {
        debug('getLogoutResponseUrl');
        const instance = this;
        this.serviceProvider.create_logout_response_url(
            instance.identityProvider,
            { in_response_to: inResponseTo, relay_state: relayState },
            function (err, logoutResponseUrl) {
                if (err) {
                    console.error('create_logout_response_url failed.');
                    console.error(err);
                    return callback(err);
                }
                return callback(null, logoutResponseUrl);
            });
    }

    private assert(req, requestId, callback) {
        debug('assert');
        if (!requestId || typeof (requestId) !== 'string')
            return callback(new Error('assert needs a requestId to verify the SAML assertion.'));

        const options = { request_body: req.body };
        this.serviceProvider.post_assert(this.identityProvider, options, function (err, samlResponse) {
            if (err) {
                error('post_assert failed.');
                return callback(err);
            }

            if (!samlResponse.response_header)
                return callback(new Error('The SAML response does not have a response_header property'));
            if (!samlResponse.response_header.in_response_to)
                return callback(new Error('The SAML response\'s response_header does not have an in_response_to property.'));
            if (samlResponse.response_header.in_response_to != requestId) {
                debug('wrong request ID in SAML response, in_response_to: ' + samlResponse.response_header.in_response_to + ', requestId: ' + requestId);
                return callback(new Error('The SAML assertion does not correspond to expected request ID. Please try again.'));
            }

            debug('samlResponse:');
            debug(JSON.stringify(samlResponse, null, 2));

            // const userInfo = {
            //     authenticated_userid: SamlIdP.findSomeId(samlResponse)
            // };
            callback(null, samlResponse);
        });
    }

    // Currently not used
    /*
    private redirectAssert(req, callback) {
        debug('redirect_assert');
        if (!req.query || !req.query.SAMLRequest)
            return callback(new Error('Request does not contain a SAMLRequest query parameter. Cannot parse.'));
        const options = { request_body: req.query };
        this.serviceProvider.redirect_assert(this.identityProvider, options, function (err, samlRequest) {
            if (err) {
                debug('redirect_assert failed.');
                debug(err);
                return callback(err);
            }

            if (!samlRequest.response_header)
                return callback(new Error('The SAML Request does not have a response_header property'));
            if (!samlRequest.response_header.id)
                return callback(new Error('The SAML Request\'s response_header does not have an id property.'));

            debug('samlResponse:');
            debug(JSON.stringify(samlRequest, null, 2));

            callback(null, samlRequest);
        });
    }
    */

    private static getAttributeNames(samlResponse) {
        const attributeNames = [];
        if (samlResponse.user && samlResponse.user.attributes) {
            for (let attributeName in samlResponse.user.attributes) {
                attributeNames.push(attributeName.toLowerCase());
            }
        }
        return attributeNames;
    }

    private static getAttributeValue(samlResponse, wantedAttribute) {
        let returnValue = null;
        if (samlResponse.user && samlResponse.user.attributes) {
            for (let attributeName in samlResponse.user.attributes) {
                if (attributeName.toLowerCase() == wantedAttribute.toLowerCase()) {
                    const attributeValues = samlResponse.user.attributes[attributeName];
                    if (Array.isArray(attributeValues) && attributeValues.length > 0) {
                        returnValue = attributeValues[0];
                        break;
                    } else if (isString(attributeValues)) {
                        returnValue = attributeValues;
                        break;
                    } else {
                        debug('Found attribute ' + wantedAttribute + ', but it\'s neither an array nor a string.');
                    }
                }
            }
        }
        return returnValue;
    }

    private buildProfile(samlResponse): OidcProfile {
        debug('buildProfile()');

        const samlConfig = this.authMethodConfig;
        const profileConfig = samlConfig.profile;

        const propNames = SamlIdP.getAttributeNames(samlResponse);
        debug('Profile property names:');
        debug(propNames);

        const profileModel = {};
        for (let i = 0; i < propNames.length; ++i) {
            const prop = propNames[i];
            profileModel[prop] = SamlIdP.getAttributeValue(samlResponse, prop);
        }

        // By checking that there are mappers for "sub" and "email", we can
        // be sure that we can map this to an OidcProfile.
        const profile = {} as OidcProfile;
        for (let propName in profileConfig) {
            const propConfig = profileConfig[propName];
            if (isLiteral(propConfig))
                profile[propName] = propConfig;
            else if (isString(propConfig))
                profile[propName] = mustache.render(propConfig, profileModel);
            else
                warn(`buildProfile: Unknown type for property name ${propName}, expected number, boolean or string (with mustache templates)`);
        }
        if (samlConfig.trustUsers)
            profile.email_verified = true;
        debug('Built profile:');
        debug(profile);

        return profile;
    }
}

function isString(ob) {
    return (ob instanceof String || typeof ob === "string");
}

function isBoolean(ob) {
    return (typeof ob === 'boolean');
}

function isNumber(ob) {
    return (typeof ob === 'number');
}

function isLiteral(ob) {
    return isBoolean(ob) || isNumber(ob);
}