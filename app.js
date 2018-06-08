'use strict';

const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:app');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const logger = require('morgan');
const wicked = require('wicked-sdk');
const passport = require('passport');
//const csurf = require('csurf');

const session = require('express-session');
// const FileStore = require('session-file-store')(session);
const redisConnection = require('./common/redis-connection');

const google = require('./providers/google');
const github = require('./providers/github');
const twitter = require('./providers/twitter');
const facebook = require('./providers/facebook');
const adfs = require('./providers/adfs');

const LocalIdP = require('./providers/local');
const DummyIdP = require('./providers/dummy');
const GithubIdP = require('./providers/github');
const GoogleIdP = require('./providers/google');
const TwitterIdP = require('./providers/twitter');
const FacebookIdP = require('./providers/facebook');
const AdfsIdP = require('./providers/adfs');
const SamlIdP = require('./providers/saml');

const utils = require('./common/utils');
const utilsOAuth2 = require('./common/utils-oauth2');

// Use default options, see https://www.npmjs.com/package/session-file-store
const sessionStoreOptions = {};

const SECRET = 'ThisIsASecret';

let sessionMinutes = 60;
if (process.env.AUTH_SERVER_SESSION_MINUTES) {
    info('Using session duration specified in env var AUTH_SERVER_SESSION_MINUTES.');
    sessionMinutes = Number(process.env.AUTH_SERVER_SESSION_MINUTES);
}
debug('Session duration: ' + sessionMinutes + ' minutes.');


const app = express();

app.initApp = function (authServerConfig, callback) {
    // Store auth Config with application
    app.authConfig = authServerConfig;

    if (!wicked.isDevelopmentMode()) {
        app.set('trust proxy', 1);
        // TODO: This is not deal-breaking, as we're in a quite secure surrounding anyway,
        // but currently Kong sends 'X-Forwarded-Proto: http', which is plain wrong. And that
        // prevents the securing of the cookies. We know it's okay right now, so we do it
        // anyway - the Auth Server is SSL terminated at HAproxy, and the rest is http but
        // in the internal network of Docker.

        //sessionArgs.cookie.secure = true;
        info("Running in PRODUCTION MODE.");
    } else {
        warn("=============================");
        warn(" Running in DEVELOPMENT MODE");
        warn("=============================");
        warn("If you see this in your production logs, you're doing something wrong.");
    }

    const basePath = app.get('base_path');

    app.use(basePath + '/bootstrap', express.static(path.join(__dirname, 'node_modules/bootstrap/dist')));
    app.use(basePath + '/jquery', express.static(path.join(__dirname, 'node_modules/jquery/dist')));
    app.use(basePath + '/content', utils.serveStaticContent);

    app.use(wicked.correlationIdHandler());

    // view engine setup
    app.set('views', path.join(__dirname, 'views'));
    app.set('view engine', 'jade');

    logger.token('correlation-id', function (req, res) {
        return req.correlationId;
    });
    app.use(logger('{"date":":date[clf]","method":":method","url":":url","remote-addr":":remote-addr","version":":http-version","status":":status","content-length":":res[content-length]","referrer":":referrer","response-time":":response-time","correlation-id":":correlation-id"}'));

    //const csrfProtection = csurf({ cookie: true });
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));

    // Set up the cookie parser
    app.use(cookieParser(SECRET));
    // Specify the session arguments. Used for configuring the session component.
    var sessionArgs = {
        name: 'portal-auth.cookie.sid',
        store: redisConnection.createSessionStore(session),
        secret: SECRET,
        saveUninitialized: true,
        resave: false,
        cookie: {
            maxAge: sessionMinutes * 60 * 1000
        }
    };

    // And session management
    app.use(session(sessionArgs));
    // Initialize Passport
    app.use(passport.initialize());
    app.use(passport.session());

    app.use(function (req, res, next) {
        debug(req.session);
        next();
    });

    // =======================
    // Actual implementation
    // =======================

    // Here: Read from Auth Methods configuration in default.json
    for (let i = 0; i < authServerConfig.authMethods.length; ++i) {
        const authMethod = authServerConfig.authMethods[i];
        const authUri = `${basePath}/${authMethod.name}`;
        let enabled = true;
        if (authMethod.hasOwnProperty("enabled"))
            enabled = utils.parseBool(authMethod.enabled);
        if (!enabled) {
            info(`Skipping disabled auth method ${authMethod.name}.`);
            continue;
        }
        const options = {
            externalUrlBase: app.get('external_url'),
            basePath: app.get('base_path')
        };
        info(`Activating auth method ${authMethod.name} with type ${authMethod.type}.`);
        switch (authMethod.type) {
            case "local":
                app.use(authUri, new LocalIdP(basePath, authMethod.name, authMethod.config, options).getRouter());
                break;
            case "dummy":
                app.use(authUri, new DummyIdP(basePath, authMethod.name, authMethod.config, options).getRouter());
                break;
            case "github":
                app.use(authUri, new GithubIdP(basePath, authMethod.name, authMethod.config, options).getRouter());
                break;
            case "google":
                app.use(authUri, new GoogleIdP(basePath, authMethod.name, authMethod.config, options).getRouter());
                break;
            case "twitter":
                app.use(authUri, new TwitterIdP(basePath, authMethod.name, authMethod.config, options).getRouter());
                break;
            default:
                error('ERROR: Unknown authMethod type ' + authMethod.type);
                break;
        }
    }

    app.get(basePath + '/profile', utilsOAuth2.getProfile);

    app.get(basePath + '/logout', function (req, res, next) {
        debug(basePath + '/logout');
        req.session.destroy();
        if (req.query && req.query.redirect_uri)
            return res.redirect(req.query.redirect_uri);
        res.render('logout', {
            title: 'Logged out',
            portalUrl: wicked.getExternalPortalUrl(),
            baseUrl: req.app.get('base_path'),
            correlationId: req.correlationId,
        });
    });

    app.get(basePath + '/failure', function (req, res, next) {
        debug(basePath + '/failure');

        let redirectUri = null;
        if (req.session && req.session.redirectUri)
            redirectUri = req.session.redirectUri;

        res.render('failure', {
            title: 'Failure',
            portalUrl: wicked.getExternalPortalUrl(),
            baseUrl: req.app.get('base_path'),
            correlationId: req.correlationId,
            returnUrl: redirectUri
        });
    });

    // =======================

    // catch 404 and forward to error handler
    app.use(function (req, res, next) {
        const err = new Error('Not Found');
        err.status = 404;
        next(err);
    });

    // production error handler
    // no stacktraces leaked to user
    app.use(function (err, req, res, next) {
        if (err.status !== 404) {
            error(err);
        }
        res.status(err.status || 500);
        // From failJson?
        if (err.issueAsJson) {
            res.json({
                status: err.status || 500,
                message: err.message,
                internal_error: err.internalError
            });
        } else if (err.oauthError) {
            // From failOAuth
            // RFC 6749 compatible JSON error
            res.json({
                error: err.oauthError,
                error_description: err.message
            });
        } else {
            res.render('error', {
                title: 'Error',
                portalUrl: wicked.getExternalPortalUrl(),
                baseUrl: req.app.get('base_path'),
                correlationId: req.correlationId,
                message: err.message,
                status: err.status
            });
        }
    });

    callback(null);
};

module.exports = app;
