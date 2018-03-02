'use strict';

const cors = require('cors');
const debug = require('debug')('portal-auth:utils');
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
        url: apiUrl
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
        console.error('storeRedirectUriForCors() - Invalid URI: ' + uri);
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
                console.error(ex);
            }
        }
        if (!utils._packageVersion) // something went wrong
            utils._packageVersion = "0.0.0";
    }
    return utils._packageVersion;
};


module.exports = utils;