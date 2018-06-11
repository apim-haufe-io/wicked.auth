'use strict';

import * as request from 'request';
import { StatusError } from '../common/utils-fail';
const { debug, info, warn, error } = require('portal-env').Logger('portal-auth:kong-utils');
const wicked = require('wicked-sdk');

import { utils } from '../common/utils';

function kongAction(method, url, body, expectedStatusCode, callback) {
    //console.log('$$$$$$ kongAction: ' + method + ' ' + url);
    //console.log(body);
    debug('kongAction(), ' + method + ', ' + url);

    // If for some reason, we think Kong is not available, tell the upstream
    // if (!utils._kongAvailable) {
    //     const err = new Error('kong admin end point not available: ' + utils._kongMessage);
    //     err.status = 500;
    //     return callback(err);
    // }

    // Now do our thing
    var kongUrl = wicked.getInternalKongAdminUrl();
    var methodBody = {
        method: method,
        url: kongUrl + url,
        json: null,
        body: null
    };
    if (method != 'DELETE' &&
        method != 'GET') {
        methodBody.json = true;
        methodBody.body = body;
        if (process.env.KONG_CURL)
            console.error('curl -X ' + method + ' -d \'' + JSON.stringify(body) + '\' -H \'Content-Type: application/json\' ' + methodBody.url);
    } else {
        if (process.env.KONG_CURL)
            console.error('curl -X ' + method + ' ' + methodBody.url);
    }

    request(methodBody, function (err, apiResponse, apiBody) {
        if (err)
            return callback(err);
        if (expectedStatusCode != apiResponse.statusCode) {
            const err = new StatusError(apiResponse.statusCode, 'kongAction ' + method + ' on ' + url + ' did not return the expected status code (got: ' + apiResponse.statusCode + ', expected: ' + expectedStatusCode + ').');
            debug(method + ' /' + url);
            debug(methodBody);
            debug(apiBody);
            //console.error(apiBody);
            return callback(err);
        }
        callback(null, utils.getJson(apiBody));
    });
}

export const kongUtils = {

    kongGet: function (url, callback) {
        kongAction('GET', url, null, 200, callback);
    },

    kongPost: function (url, body, callback) {
        kongAction('POST', url, body, 201, callback);
    },

    kongDelete: function (url, callback) {
        kongAction('DELETE', url, null, 204, callback);
    },

    kongPatch: function (url, body, callback) {
        kongAction('PATCH', url, body, 200, callback);
    }
};
