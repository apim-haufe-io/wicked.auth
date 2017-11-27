'use strict';

const crypto = require('crypto');
const wicked = require('wicked-sdk');
const { URL } = require('url');
const qs = require('querystring');

const debug = require('debug')('portal-auth:profile-store');
const redisConnection = require('./redis-connection');
const { failMessage, failError, failOAuth, makeError } = require('./utils-fail');

const profileStore = function () { };

profileStore._ttlSecondsMap = {};
profileStore.getTtlSeconds = function (apiId, callback) {
    debug(`getTtlSeconds(${apiId})`);
    if (profileStore._ttlSecondsMap[apiId])
        return callback(null, profileStore._ttlSecondsMap[apiId]);
    wicked.apiGet(`/apis/${apiId}`, function (err, apiConfig) {
        if (err)
            return callback(err);
        if (!apiConfig.settings)
            return failMessage(500, `getTtlSeconds: API ${apiId} does not have a settings property.`, callback);
        if (!apiConfig.settings.token_expiration)
            return failMessage(500, `getTtlSeconds: API ${apiId} does not have a settings.token_expiration property.`, callback);
        const ttlSeconds = apiConfig.settings.token_expiration - 0; // force conversion to number
        if (ttlSeconds <= 0)
            return failMessage(500, `getTtlSeconds: API ${apiId} has a token expiration of 0 or a negative number.`, callback);
        profileStore._ttlSecondsMap[apiId] = ttlSeconds;
        return callback(null, ttlSeconds);
    });
};

profileStore.registerTokenOrCode = function (tokenResponse, apiId, profile, callback) {
    if (tokenResponse.access_token) {
        // Easy case, it's a JSON answer
        return profileStore.store(tokenResponse.access_token, apiId, profile, callback);
    } else if (tokenResponse.redirect_uri) {
        // It's the answer from an implicit token, let's parse the URL
        const redir = new URL(tokenResponse.redirect_uri);
        debug(redir);
        if (redir.hash) {
            if (!redir.hash.startsWith('#'))
                return failMessage(500, 'registerToken: The redirect URI fragment does not start with a hash tag', callback);
            const queryParams = qs.parse(redir.hash.substring(1)); // cut off hash
            // Now off you go
            if (queryParams.access_token)
                return profileStore.store(queryParams.access_token, apiId, profile, callback);
            return failMessage(500, 'registerToken: The redirect URI does not contain a fragment', callback);
        }
        // If there is no hash, we might have a code
        if (redir.searchParams && redir.searchParams.get('code'))
            return profileStore.store(redir.searchParams.get('code'), apiId, profile, callback);

        return failMessage(500, 'registerToken: The redirect URI does not contain neither an access_token nor a code parameter', callback);
    }
};

profileStore.store = function (token, apiId, profile, callback) {
    debug('store()');

    profileStore.getTtlSeconds(apiId, function (err, ttlSeconds) {
        if (err)
            return callback(err);
        const profileString = JSON.stringify(profile);
        const redis = redisConnection.getRedis();
        const tokenHash = hashToken(token);
        redis.set(tokenHash, profileString, 'EX', ttlSeconds, callback);
    });
};

profileStore.retrieve = function (token, callback) {
    debug('retrieve()');

    const redis = redisConnection.getRedis();
    const tokenHash = hashToken(token);
    redis.get(tokenHash, function (err, result) {
        if (err)
            return callback(err);
        const profileJson = JSON.parse(result);
        return callback(null, profileJson);
    });
};

function hashToken(token) {
    const sha256 = crypto.createHash('sha256');
    sha256.update(token);
    return sha256.digest('hex');
}

module.exports = profileStore;
