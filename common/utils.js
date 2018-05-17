'use strict';

const cors = require('cors');
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:utils');
const wicked = require('wicked-sdk');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');
const path = require('path');
const request = require('request');

const { failMessage, failError, failOAuth, makeError } = require('./utils-fail');

const utils = function () { };

utils.getUtc = function () {
    return Math.floor((new Date()).getTime() / 1000);
};

utils.createRandomId = function () {
    return crypto.randomBytes(20).toString('hex');
};

utils.jsonError = function (res, message, status) {
    debug('Error ' + status + ': ' + message);
    res.status(status).json({ message: message });
};

utils.getJson = function (ob) {
    if (ob instanceof String || typeof ob === "string")
        return JSON.parse(ob);
    return ob;
};

utils.isPublic = function (uriName) {
    return uriName.endsWith('jpg') ||
        uriName.endsWith('jpeg') ||
        uriName.endsWith('png') ||
        uriName.endsWith('gif') ||
        uriName.endsWith('css');
};

utils.pipe = function (req, res, uri) {
    let apiUrl = wicked.getInternalApiUrl();
    if (!apiUrl.endsWith('/'))
        apiUrl += '/';
    apiUrl += uri;
    request.get({
        url: apiUrl,
        headers: { 'X-Authenticated-Scope': 'read_content' }
    }).pipe(res);
};

utils.serveStaticContent = require('express').Router();
utils.serveStaticContent.get('/*', function (req, res, next) {
    debug('serveStaticContent ' + req.path);
    if (utils.isPublic(req.path)) {
        return utils.pipe(req, res, 'content' + req.path);
    }
    res.status(404).json({ message: 'Not found.' });
});

utils.splitName = function (fullName, username) {
    debug('splitName(): fullName = ' + fullName + ', username = ' + username);
    var name = {
        firstName: '',
        lastName: fullName,
        fullName: fullName
    };
    if (!fullName) {
        if (username) {
            name.lastName = username;
            name.fullName = username;
        } else {
            name.lastName = 'Unknown';
            name.fullName = 'Unknown';
        }
    } else {
        var spaceIndex = fullName.indexOf(' ');
        if (spaceIndex < 0)
            return name;
        name.firstName = fullName.substring(0, spaceIndex);
        name.lastName = fullName.substring(spaceIndex + 1);
    }
    debug(name);
    return name;
};

utils.makeFullName = function (familyName, givenName) {
    if (familyName && givenName)
        return givenName + ' ' + familyName;
    if (familyName)
        return familyName;
    if (givenName)
        return givenName;
    return 'Unknown Username';
};

utils.makeUsername = function (fullName, username) {
    debug('makeUsername(): fullName = ' + fullName + ', username = ' + username);
    if (username)
        return username;
    return fullName;
};

const _validCorsHosts = {};
function storeRedirectUriForCors(uri) {
    debug('storeRedirectUriForCors() ' + uri);
    try {
        const parsedUri = url.parse(uri);
        const host = parsedUri.protocol + '//' + parsedUri.host;
        _validCorsHosts[host] = true;
        debug(_validCorsHosts);
    } catch (ex) {
        error('storeRedirectUriForCors() - Invalid URI: ' + uri);
    }
}

function isCorsHostValid(host) {
    debug('isCorsHostValid(): ' + host);
    if (_validCorsHosts[host]) {
        debug('Yes, ' + host + ' is valid.');
        return true;
    }
    debug('*** ' + host + ' is not a valid CORS origin.');
    return false;
}

const _allowOptions = {
    origin: true,
    credentials: true,
    allowedHeaders: [
        'Accept',
        'Accept-Encoding',
        'Connection',
        'User-Agent',
        'Content-Type',
        'Cookie',
        'Host',
        'Origin',
        'Referer'
    ]
};

const _denyOptions = {
    origin: false
};

utils.cors = function () {
    const optionsDelegate = (req, callback) => {
        const origin = req.header('Origin');
        debug('in CORS options delegate. req.headers = ');
        debug(req.headers);
        if (isCorsHostValid(origin))
            callback(null, _allowOptions); // Mirror origin, it's okay
        else
            callback(null, _denyOptions);
    };
    return cors(optionsDelegate);
};

utils._packageVersion = null;
utils.getVersion = function () {
    if (!utils._packageVersion) {
        const packageFile = path.join(__dirname, '..', 'package.json');
        if (fs.existsSync(packageFile)) {
            try {
                const packageInfo = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
                if (packageInfo.version)
                    utils._packageVersion = packageInfo.version;
            } catch (ex) {
                error(ex);
            }
        }
        if (!utils._packageVersion) // something went wrong
            utils._packageVersion = "0.0.0";
    }
    return utils._packageVersion;
};

utils._apiInfoMap = {};
utils.getApiInfo = (apiId, callback) => {
    debug(`getApiInfo(${apiId})`);
    if (utils._apiInfoMap[apiId] && utils._apiInfoMap[apiId].success)
        return callback(null, utils._apiInfoMap[apiId].data);
    wicked.apiGet(`/apis/${apiId}`, (err, apiInfo) => {
        if (err) {
            utils._apiInfoMap[apiId] = {
                success: false
            };
            return callback(err);
        }
        utils._apiInfoMap[apiId] = {
            data: apiInfo,
            success: true
        };
        return callback(null, apiInfo);
    });
};

utils.getApiRegistrationPool = (apiId, callback) => {
    debug(`getApiRegistrationPool(${apiId})`);
    utils.getApiInfo(apiId, (err, apiInfo) => {
        if (err)
            return callback(err);
        let poolId = apiInfo.registrationPool;
        if (!poolId)
            debug(`API ${apiId} does not have a registration pool setting`);
        // Yes, poolId can be null or undefined here
        return callback(null, poolId);
    });
};

utils._poolInfoMap = {};
utils.getPoolInfo = (poolId, callback) => {
    debug(`getPoolInfo(${poolId})`);
    if (utils._poolInfoMap[poolId] && utils._poolInfoMap[poolId].success)
        return callback(null, utils._poolInfoMap[poolId].data);
    wicked.apiGet(`/pools/${poolId}`, (err, poolInfo) => {
        if (err) {
            utils._poolInfoMap[poolId] = {
                success: false
            };
            return callback(err);
        }
        utils._poolInfoMap[poolId] = {
            data: poolInfo,
            success: true
        };
        return callback(null, poolInfo);
    });
};

utils.getPoolInfoByApi = (apiId, callback) => {
    debug(`getPoolInfoByApi(${apiId})`);
    utils.getApiRegistrationPool(apiId, (err, poolId) => {
        if (err)
            return callback(err);
        if (!poolId)
            return callback(utils.makeError(`API ${apiId} does not have a registration pool`, 500));
        utils.getPoolInfo(poolId, callback);
    });
};


module.exports = utils;