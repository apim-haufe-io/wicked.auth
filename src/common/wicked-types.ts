'use strict';

// ===============
// WICKED TYPES
// ===============

export interface WickedUserInfo {
    id: string,
    customId?: string,
    email?: string,
    password?: string,
    validated?: boolean,
    groups: string[]
}

export interface WickedUserCreateInfo {
    customId?: string,
    email: string,
    password?: string,
    validated: boolean,
    groups: string[]
}

export interface WickedApi {
    id: string,
    name: string,
    desc: string,
    auth: string,
    authServers?: string[],
    authMethods?: string[],
    registrationPool?: string,
    settings: WickedApiSettings
}

export interface WickedApiSettings {
    enable_client_credentials?: boolean,
    enable_implicit_grant?: boolean,
    enable_authorization_code?: boolean,
    enable_password_grant?: boolean,
    token_expiration?: string,
    scopes: WickedApiScopes,
    tags: string[],
    requiredGroup?: string,
    plans: string[],
    internal?: boolean
}

export interface WickedApiScopes {
    [scope: string]: {
        description: string
    }
}

export interface WickedGrant {
    scope: string,
    grantedDate: string // DateTime
}

export interface WickedGrantCollection {
    items: WickedGrant[]
}

export interface WickedAuthMethod {
    enabled: string,
    name: string,
    type: string,
    friendlyShort: string,
    friendlyLong: string,
    config: any
}

export interface WickedAuthServer {
    id: string,
    name: string,
    authMethods: WickedAuthMethod[],
    config: {
        api: KongApi,
        plugins: KongPlugin[]
    }
}

export enum WickedOwnerRole {
    Owner = "owner",
    Collaborator = "collaborator",
    Reader = "reader"
}

export interface WickedOwner {
    userId: string,
    email: string,
    role: WickedOwnerRole
}

export interface WickedApplication {
    id: string,
    name: string,
    redirectUri: string,
    confidential: boolean,
    ownerList: WickedOwner[]   
}

export enum WickedAuthType {
    KeyAuth = "key-auth",
    OAuth2 = "oauth2"
}

export interface WickedSubscription {
    application: string,
    api: string,
    plan: string,
    auth: WickedAuthType,
    apikey?: string,
    clientId?: string,
    clientSecret?: string,
    approved: boolean,
    trusted?: boolean
}

export interface WickedSubscriptionInfo {
    application: WickedApplication,
    subscription: WickedSubscription
}

export enum WickedPoolPropertyType {
    String = "string"
}

export interface WickedPoolProperty {
    description: string,
    type: string,
    maxLength: number,
    minLength: number,
    required: boolean,
    oidcClaim: string
}

export interface WickedPool {
    id: string,
    name: string,
    properties: WickedPoolProperty[]
}

// Wicked Callback Types

export interface WickedApiCallback {
    (err, wickedApi?: WickedApi): void
}

export interface WickedPoolCallback {
    (err, poolInfo?: WickedPool): void
}

// ===============
// KONG TYPES
// ===============

export interface KongApi {
    retries: number,
    upstream_send_timeout: number,
    upstream_connect_timeout: number,
    id: string,
    upstream_read_timeout: number,
    strip_uri: boolean,
    created_at: number,
    upstream_url: string,
    name: string,
    uris: string[],
    preserve_host: boolean,
    http_if_terminated: boolean,
    https_only: boolean
}

export interface KongPlugin {
    name: string,
    config: any
}

// Kong Callback Types

export interface KongApiCallback {
    (err, kongApi?: KongApi): void
}
