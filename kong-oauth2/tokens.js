'use strict';

const async = require('async');
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:tokens');
const qs = require('querystring');

const utils = require('../common/utils');
const kongUtils = require('./kong-utils');
const { failOAuth, failJson } = require('../common/utils-fail');
// const failOAuth = utils.failOAuth;
// const fail = utils.fail;

const tokens = function () { };

tokens.getTokenDataByAccessToken = function (accessToken, callback) {
    debug('getTokenDataByAccessToken()');
    return tokens.getTokenData(accessToken, null, callback);
};

tokens.getTokenDataByRefreshToken = function (refreshToken, callback) {
    debug('getTokenDataByRefreshToken()');
    return tokens.getTokenData(null, refreshToken, callback);
};

tokens.getTokenData = function (accessToken, refreshToken, callback) {
    debug('getTokenData(), access_token = ' + accessToken + ', refresh_token = ' + refreshToken);
    let tokenUrl = 'oauth2_tokens?';
    if (accessToken)
        tokenUrl = tokenUrl + 'access_token=' + qs.escape(accessToken);
    else if (refreshToken)
        tokenUrl = tokenUrl + 'refresh_token=' + qs.escape(refreshToken);
    kongUtils.kongGet(tokenUrl, function (err, resultList) {
        if (err) {
            return failJson(500, 'could not retrieve token information from Kong', err, callback);
        }

        if (resultList.total <= 0 || !resultList.data || resultList.data.length <= 0) {
            return failJson(404, 'not found', callback);
        }

        return callback(null, resultList.data[0]);
    });
};

tokens.deleteTokensByAccessToken = function (accessToken, callback) {
    debug('deleteTokensByAccessToken()');
    tokens.deleteTokens(accessToken, null, callback);
};

tokens.deleteTokensByAuthenticatedUserId = function (authenticatedUserId, callback) {
    debug('deleteTokensByAuthenticatedUserId()');
    tokens.deleteTokens(null, authenticatedUserId, callback);
};

tokens.deleteTokens = function (accessToken, authenticatedUserId, callback) {
    debug('deleteTokens(), accessToken = ' + accessToken + ', authenticatedUserId = ' + authenticatedUserId);

    // This function is called below with a list of access tokens, depending on how
    // the tokens are gathered (either directly, a single token, or by a user id)
    const kongDeleteTokens = function (tokenList) {
        async.mapSeries(tokenList, function (token, callback) {
            utils.kongDelete('oauth2_tokens/' + qs.escape(token), callback);
        }, function (err, results) {
            if (err) {
                return failJson(500, 'Deleting tokens failed. See log for details.', callback);
            }

            return callback(null); // Success
        });
    };

    if (accessToken) {
        // Delete single token mode
        return kongDeleteTokens([accessToken]);
    } else if (authenticatedUserId) {
        // First get the list of access tokens by user id
        utils.kongGet('oauth2_tokens?authenticated_userid=' + qs.escape(authenticatedUserId), function (err, result) {
            if (err) {
                return failJson(500, 'Kong did not return desired access tokens.', callback);
            }
            if (!result.data || !Array.isArray(result.data)) {
                return failJson(500, 'Kong returned an invalid result (data is not present or not an array).', callback);
            }
            const tokenList = [];
            for (let i = 0; i < result.data.length; ++i) {
                tokenList.push(result.data[i].access_token);
            }
            return kongDeleteTokens(tokenList);
        });
    } else {
        return failJson(400, 'Bad request. Needs either access_token or authenticated_userid.', callback);
    }
};

module.exports = tokens;