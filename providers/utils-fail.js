const failUtils = function () { };

failUtils.makeError = function (message, status) {
    const err = new Error(message);
    if (status)
        err.status = status;
    else
        err.status = 500;
    return err;
};

failUtils.failMessage = function (statusCode, message, callback) {
    const err = new Error(message);
    err.status = statusCode;
    return callback(err);
};

failUtils.failOAuth = function (statusCode, error, message, internalError, callback) {
    const err = new Error(message);
    err.oauthError = error;
    err.status = statusCode;
    if (typeof(internalError) === 'function')
        callback = internalError;
    else
        err.internalError = internalError;
    return callback(err);
};

failUtils.failError = function (statusCode, err, callback) {
    // Don't overwrite pre-existing status codes.
    if (!err.status)
        err.status = statusCode;
    return callback(err);
};

module.exports = failUtils;
