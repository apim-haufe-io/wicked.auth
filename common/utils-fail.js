const failUtils = function () { };

failUtils.makeError = function (message, status) {
    const err = new Error(message);
    if (status)
        err.status = status;
    else
        err.status = 500;
    return err;
};

// Makes sure the application fails with a HTML generated error
// message; use for UI failures.
failUtils.failMessage = function (statusCode, message, callback) {
    const err = new Error(message);
    err.status = statusCode;
    return callback(err);
};

// Makes sure the app returns a OAuth2 compliant error message:
// {
//   "error": "some oauth2 error",
//   "error_description": "nice description"   
// }
failUtils.failOAuth = function (statusCode, oauthError, message, internalErrorOrCallback, callback) {
    const err = new Error(message);
    err.oauthError = oauthError;
    err.status = statusCode;
    if (typeof(internalErrorOrCallback) === 'function')
        callback = internalErrorOrCallback;
    else
        err.internalError = internalErrorOrCallback;
    return callback(err);
};

// Makes sure the app returns a JSON error message
// {
//   "status": <status code>
//   "message": "the message"
//   "error": <the internal error if applicable>
// }
failUtils.failJson = function (status, message, internalErrorOrCallback, callback) {
    const err = new Error(message);
    err.issueAsJson = true;
    err.status = status;
    if (typeof (internalErrorOrCallback) === 'function')
        callback = internalErrorOrCallback;
    else
        err.internalError = internalErrorOrCallback;
    return callback(err);
};

failUtils.failError = function (statusCode, err, callback) {
    // Don't overwrite pre-existing status codes.
    if (err.statusCode && !err.status)
        err.status = err.statusCode;
    if (!err.status)
        err.status = statusCode;
    return callback(err);
};

module.exports = failUtils;
