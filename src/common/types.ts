import { WickedApiScopes } from "./wicked-types";

'use strict';

export interface OAuth2Request {
    api_id: string,
    auth_method: string,
    client_id: string,
    // client_secret is not needed for all flows, e.g. implicit
    client_secret?: string,
    // Not needed for client_credentials
    authenticated_userid?: string,
    scope?: any,
    // Hmm
    session_data?: any
}

export interface TokenRequest extends OAuth2Request {
    grant_type: string,
    code?: string,
    username?: string,
    password?: string,
    refresh_token?: string
}

export interface AuthRequest extends OAuth2Request {
    response_type: string,
    redirect_uri?: string,
    state?: string,
    prompt?: string,
    trusted?: boolean,
    scopesDiffer?: boolean,
    plain?: boolean
}

export interface AuthRequestCallback {
    (err, authRequest?: AuthRequest): void
}

export interface AuthResponse {
    userId?: string,
    customId?: string,
    defaultProfile: OidcProfile,
    defaultGroups: string[],
    registrationPool?: string,
    profile?: OidcProfile
}

export interface AuthResponseCallback {
    (err, authResponse?: AuthResponse): void
};

export interface AuthSession {
    authRequest: AuthRequest,
    authResponse?: AuthResponse,
    tmpAuthResponse?: AuthResponse,
    registrationNonce?: string
};

export interface OidcProfile {
    sub: string,
    email?: string,
    email_verified?: boolean,
    preferred_username?: string,
    username?: string,
    name?: string,
    given_name?: string,
    family_name?: string,
    phone?: string
};

export interface EndpointDefinition {
    method: string,
    uri: string,
    handler: ExpressHandler,
    middleware?: ExpressHandler
};

export interface CheckRefreshDecision {
    allowRefresh: boolean
};

export interface CheckRefreshCallback {
    (err, checkRefreshDecision?: CheckRefreshDecision): void
};

export interface IdentityProvider {
    getType: () => string,
    getRouter: () => any,
    authorizeWithUi: (req, res, authRequest: AuthRequest) => void,
    endpoints: () => EndpointDefinition[],
    authorizeByUserPass: (user: string, pass: string, callback: AuthResponseCallback) => void,
    checkRefreshToken: (tokenInfo, callback: CheckRefreshCallback) => void
};

export interface IdpOptions {
    externalUrlBase: string,
    basePath: string
};

export interface LocalIdpConfig {
    trustUsers: boolean
};

export interface OAuth2IdpConfig {
    clientId: string,
    clientSecret: string
}

export interface GithubIdpConfig extends OAuth2IdpConfig {
};

export interface GoogleIdpConfig extends OAuth2IdpConfig {
};

export interface TwitterIdpConfig {
    consumerKey: string,
    consumerSecret: string
};

export interface DummyIdpConfig {
};

export interface ExpressHandler {
    (req, res, next?): void
};

export interface EmailMissingHandler {
    (req, res, next, customId): void
};

export interface TokenInfo {
    access_token: string,
    refresh_token: string,
    authenticated_userid?: string,
    authenticated_scope?: string
};

export interface KongTokenInfo {
    data: TokenInfo[]
};

export interface TokenInfoCallback {
    (err, tokenInfo?: TokenInfo): void
};

export interface TokenResponse {
    access_token?: string,
    redirect_uri?: string
};

export interface SimpleCallback {
    (err): void
};

export interface NumberCallback {
    (err, n?: number): void
};

export interface OidcProfileCallback {
    (err, profile?: OidcProfile): void
};

export interface WickedApiScopesCallback {
    (err, apiScopes?: WickedApiScopes): void
};

export interface SubscriptionValidation {
    trusted: boolean
};

export interface SubscriptionValidationCallback {
    (err, subscriptionValidation?: SubscriptionValidation): void
};

export interface ValidatedScopes {
    scopesDiffer: boolean,
    validatedScopes: string[]
};

export interface ValidatedScopesCallback {
    (err, validatedScopes?: ValidatedScopes): void
};

export interface StringCallback {
    (err, s?: string): void
};

export interface AccessToken {
    access_token: string,
    refresh_token?: string,
    token_type: string,
    expires_in: number,
    // This doesn't belong here:
    session_data?: any
}

export interface AccessTokenCallback {
    (err, accessToken?: AccessToken): void
}

export interface NameSpec {
    fullName: string,
    firstName?: string,
    lastName?: string
}
