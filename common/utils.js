'use strict';

const cors = require('cors');
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:utils');
const wicked = require('wicked-sdk');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');
const path = require('path');
const request = require('request');
const qs = require('querystring');

const { failMessage, failError, failOAuth, makeError } = require('./utils-fail');

const ERROR_TIMEOUT = 500; // ms

const utils = function () { };

utils.init = (app) => {
    debug('init()');
    utils.app = app;
};

utils.getUtc = function () {
    return Math.floor((new Date()).getTime() / 1000);
};

utils.createRandomId = function () {
    return crypto.randomBytes(20).toString('hex');
};

utils.clone = (o) => {
    // Ahem.
    return JSON.parse(JSON.stringify(o));
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

// https://stackoverflow.com/questions/263965/how-can-i-convert-a-string-to-boolean-in-javascript
utils.parseBool = (str) => {
    debug(`parseBool(${str})`);
    if (str == null)
        return false;

    if (typeof (str) === 'boolean')
        return (str === true);

    if (typeof (str) === 'string') {
        if (str == "")
            return false;

        str = str.replace(/^\s+|\s+$/g, '');
        if (str.toLowerCase() == 'true' || str.toLowerCase() == 'yes')
            return true;

        str = str.replace(/,/g, '.');
        str = str.replace(/^\s*\-\s*/g, '-');
    }

    if (!isNaN(str))
        return (parseFloat(str) != 0);

    return false;
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

utils.getExternalUrl = () => {
    debug(`getExternalUrl()`);
    return utils.app.get('external_url');
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
            name.lastName = '';
            name.fullName = username;
        } else {
            name.lastName = '';
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

utils.verifyRecaptcha = (req, callback) => {
    if (req.app.glob.recaptcha && req.app.glob.recaptcha.useRecaptcha) {
        var secretKey = req.app.glob.recaptcha.secretKey;
        var recaptchaResponse = req.body['g-recaptcha-response'];
        request.post({
            url: 'https://www.google.com/recaptcha/api/siteverify',
            formData: {
                secret: secretKey,
                response: recaptchaResponse
            }
        }, function (err, apiResponse, apiBody) {
            if (err)
                return callback(err);
            var recaptchaBody = utils.getJson(apiBody);
            if (!recaptchaBody.success) {
                let err = new Error('ReCAPTCHA response invalid - Please try again');
                err.status = 403;
                return callback(err);
            }

            callback(null);
        });
    } else {
        callback(null);
    }
};

utils.createVerificationRequest = (trustUsers, authMethodId, email, callback) => {
    debug(`createVerificationRequest(${authMethodId}, ${email})`);

    if (trustUsers) {
        debug('not creating verification requests, users are implicitly trusted');
        return callback(null);
    }

    // Assemble the link to the verification page:
    // const globals = wicked.getGlobals();
    const authUrl = utils.getExternalUrl();
    const verificationLink = `${authUrl}/${authMethodId}/verify/{{id}}`;

    // Now we need to create a verification request with the wicked API (as the machine user)
    const verifBody = {
        type: 'email',
        email: email,
        link: verificationLink
    };
    wicked.apiPost('/verifications', verifBody, callback);
};

utils.createViewModel = (req, authMethodId) => {
    const csrfToken = utils.createRandomId();
    req.session.csrfToken = csrfToken;
    return {
        title: req.app.glob.title,
        portalUrl: wicked.getExternalPortalUrl(),
        baseUrl: req.app.get('base_path'),
        csrfToken: csrfToken,
        loginUrl: `${authMethodId}/login`,
        logoutUrl: `logout`,
        signupUrl: `${authMethodId}/signup`,
        registerUrl: `${authMethodId}/register`,
        forgotPasswordUrl: `${authMethodId}/forgotpassword`,
        verifyEmailUrl: `${authMethodId}/verifyemail`,
        verifyPostUrl: `${authMethodId}/verify`,
        emailMissingUrl: `${authMethodId}/emailmissing`,
        recaptcha: req.app.glob.recaptcha
    };
};

utils.getAndDeleteCsrfToken = (req) => {
    debug('getAndDeleteCsrfToken()');
    const csrfToken = req.session.csrfToken;
    delete req.session.csrfToken;
    return csrfToken;
};

/**
 * Checks for a user by custom ID.
 * 
 * @param {*} customId custom ID to check a user for; if there is a user
 * with this custom ID in the wicked database, the user will already have
 * an email address, and thus the IdP would not have to ask for one, in
 * case it doesn't provide one (e.g. Twitter).
 * @param {*} callback Returns (err, shortUserInfo), shortUserInfo may be
 * null in case the user doesn't exist, otherwise { id, customId, name, email }
 */
utils.getUserByCustomId = (customId, callback) => {
    debug(`getUserByCustomId(${customId})`);
    wicked.apiGet(`/users?customId=${qs.escape(customId)}`, (err, shortInfoList) => {
        if (err && err.statusCode == 404) {
            // Not found
            return callback(null, null);
        } else if (err) {
            // Unexpected error
            return callback(err);
        }

        // Now we should have the user ID here:
        if (!Array.isArray(shortInfoList) || shortInfoList.length <= 0 || !shortInfoList[0].id)
            return callback(new Error('getUserByCustomId: Get user short info by email did not return a user id'));
        return callback(null, shortInfoList[0]);
    });
};

/**
 * Returns `true` if the user has an established session with the given `authMethodId`. The function
 * also checks whether the user has a "profile, which is required if the user is truly logged in.
 * 
 * @param {*} req The incoming request
 * @param {*} authMethodId The auth method id this request applies to
 */
utils.isLoggedIn = (req, authMethodId) => {
    let isLoggedIn = false;
    if (req.session &&
        req.session[authMethodId] &&
        req.session[authMethodId].authResponse &&
        req.session[authMethodId].authResponse.profile)
        isLoggedIn = true;
    debug(`isLoggedIn(${authMethodId}): ${isLoggedIn}`);
    return isLoggedIn;
};

/**
 * Returns the associated user OIDC profile if the user is logged in; otherwise an Error is thrown.
 * 
 * @param {*} req 
 * @param {*} authMethodId 
 */
utils.getProfile = (req, authMethodId) => {
    if (!utils.isLoggedIn(req, authMethodId))
        throw new Error('Cannot get profile if not logged in');
    return req.session[authMethodId].authResponse.profile;
};

module.exports = utils;
