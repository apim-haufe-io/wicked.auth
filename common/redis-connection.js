'use strict';

var { debug, info, warn, error } = require('portal-env').Logger('portal:sessionstore');
const redis = require('redis');
var wicked = require('wicked-sdk');

const redisConnection = function () { };

function resolveRedis() {
    debug('resolveRedis()');

    const globals = wicked.getGlobals();

    let sessionStoreType = 'file';
    if (globals.sessionStore && globals.sessionStore.type) {
        sessionStoreType = globals.sessionStore.type;
    } else {
        throw new Error('Missing sessionStore global property, must be set to "redis".');
    }

    if (sessionStoreType === 'file') {
        throw new Error('Missing sessionStore global property, or type is set to "file", must be set to "redis".');
    }

    const settings = {
        host: globals.sessionStore.host || 'portal-redis',
        port: globals.sessionStore.port || 6379
    };
    if (globals.sessionStore.password)
        settings.password = globals.sessionStore.password;
    
    return settings;
}

redisConnection._redisConnection = null;
redisConnection.getRedis = function () {
    debug('getRedis()');

    if (redisConnection._redisConnection)
        return redisConnection._redisConnection;

    const redisSettings = resolveRedis();
    redisConnection._redisConnection = redis.createClient({
        host: redisSettings.host,
        port: redisSettings.port,
        password: redisSettings.password
    });
    return redisConnection._redisConnection;
};

redisConnection.createSessionStore = function (session) {
    debug('createSessionStore()');

    const redisSettings = resolveRedis();

    const sessionStoreOptions = {};
    let SessionStore = require('connect-redis')(session);
    // Set options for Redis session store, see https://www.npmjs.com/package/connect-redis
    // Use the predefined client, no need to create a second one.
    sessionStoreOptions.client = redisConnection.getRedis();

    debug('Using redis session store with options ' + sessionStoreOptions);

    return new SessionStore(sessionStoreOptions);
};

module.exports = redisConnection;
