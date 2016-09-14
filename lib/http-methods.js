/**
 * @module module:http-methods
 * @description
 * Private module which exports the supported http methods
 * as an array of strings.
 *
 * The {@link module:http-methods~httpMethods HTTP methods Array}
 */
'use strict';

/**
 * @name httpMethods
 */
const httpMethods = [
	'checkout', 'copy', 'delete', 'get', 'head', 'lock', 'merge',
	'mkactivity', 'mkcol', 'move', 'm-search', 'notify', 'options',
	'patch', 'post', 'purge', 'put', 'report', 'search', 'subscribe',
	'trace', 'unlock', 'unsubscribe'
];

/**
 * Only exports the HTTP methods Array
 */
module.exports = httpMethods;
