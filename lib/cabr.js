/**
 * @module module:cabr
 * @description
 * <pre>$ <kbd>NODE_DEBUG=cabr</kbd></pre>
 *
 * The cabr module, which holds the CABR class.
 *
 * The {@link module:cabr~CABR CABR class} provides rbac-a support for express/connect
 * applications.
 */

'use strict';

const log = require('util').debuglog('cabr');
const _ = require('lodash');
const Promise = require('bluebird');
const mung = require('express-mung');
const httpMethods = require('./http-methods');

class CABR {

	/**
	 * Constructs a new instance of CABR.
	 * @class CABR
	 * @param rbac {Object} The {@link https://github.com/yanickrochon/rbac-a#rbac-a RBAC-A} instance to use
	 * @param [options] {Object} The options to setup the class
	 * @param [options.userProvider] {Object} An RBAC-A provider which get method will be called with the current
	 * request to determine the current user. Defaults to the provider of the passed rbac instance.
	 * @param [options.routes] {Object} An object of regular expression strings mapped to a string or array of strings
	 * (see the {@link https://github.com/yanickrochon/rbac-a#grouped-permissions RBAC-A Grouped permissions syntax}),
	 * or an object with keys defining HTTP methods (upper or lowercase) mapped to a permission syntax string or array.
	 * The keys of the route object are used as regular expressions to determine if a route configuration applies for
	 * the current request.
 	 * @param [options.unauthorizedHandler] {Function} A middleware function that is called if a permission or attribute
	 * validation failed. Defaults to a simple function sending a 401 status and calling the next handler with an error
	 * message. The failed permission or attribute is attached as rbacFailed to the request object.
	 * @example
	 * const rbac = require('rbac-a');
	 * const CABR = require('cabr');
	 *
	 * // init the rbac instance ...
	 *
	 * const routes = {
	 *	// every route, every HTTP method needs the awesome permission
	 *	'.*': 'awesome',
	 *
	 * 	// every route, every HTTP method needs the 'awesome', yolo' and 'funky' permission
	 *	'^\/funky': ['yolo', 'funky'],
	 *
	 *	// every route, every HEAD request needs the 'clever' and 'smart' permission
	 * 	// plus the 'awesome' permission
	 *	'.*': {HEAD: ['clever', 'smart']}, // or 'clever && smart'
	 *
	 *	// every route, every COPY request needs the either the 'clever' or 'smart' permission
	 * 	// plus the 'awesome' permission
	 *	'.*': {COPY: 'clever || smart']},
	 *
	 *	// ALL HTTP methods for '/pets' will be checked with the 'pets.read'
	 *	// permission and 'awesome' permissions
	 *	'\/pets': 'pets.read',
	 *
	 *	// Custom config for '/cats', different HTTP methods
	 *	// will apply different permissions
	 *	'\/pets\/cats': {GET: 'pets.read', POST: 'cats.create', DELETE: ['pets.create', 'pets.delete']},
	 * };
	 *
	 * // init the cabr instance
	 * const cabr = new CABR(rbac, {routes});
	 *
	 * // use a custom user provider
	 * const get = (req) => Promise.resolve(req.user);
	 * cabr = new CABR(rbac, {routes, userProvider: {get}});
	 */
	constructor(rbac, options) {
		if (!rbac || !(typeof rbac.check === 'function')) {
			throw new Error('Invalid options or rbac-a instance!');
		}

		this.rbac = rbac;
		this.map = Object.create(null);
		this.postMap = Object.create(null);

		const defaultOptions = {
			userProvider: this.rbac.provider,
			routes: {},
			unauthorizedHandler
		};

		this.options = _.defaults(options || {}, defaultOptions);
		// setup the route mapping with the initial options map
		_.map(this.options.routes, (v, k) => this.registerRoute(k, v));
	}

	/**
	 * Register an {@link http://expressjs.com/en/4x.html#app express app}
	 * on this CABR instance. All mapped requests will be validated with the configured
	 * RBAC-A permissions. For all attributes of a role, the RBAC-A attribute function
	 * will be called with params.permissions: permissions object, params.req: request
	 * and params.res: response for request validation, and additionally params.body for response
	 * validation and manipulation, after all other middleware has been called.
	 * The registerApp method must be called before any route handling middleware is registered
	 * that modifies the response body, also note that it may cause errors if the response body
	 * object is dereferenced in an attribute function!
	 * @param app {Object} The express app to register.
	 * @example
	 * const express = require('express');
	 * const cabr = new CABR(...);
	 * const app = express();
	 *
	 * cabr.registerApp(app).use(...);
	 *
	 * // or
	 * const cabredApp = cabr.registerApp(express());
	 */
	registerApp(app) {
		app.use(pre.bind(this));
		app.use(mung.jsonAsync(post.bind(this)));
		return app;
	}

	/**
	 * Add a route configuration at runtime. CABR supports dynamically building the route
	 * configuration.
	 * @param route {String} String used as a regular expression. The route the permissions should be applied to
	 * @param permissions {Array[]|Array|String|Object} The permission object. The same formats as for the route
	 * options are supported. Also see the
	 * {@link https://github.com/yanickrochon/rbac-a#grouped-permissions RBAC-A Grouped permissions syntax}.
	 * @example
	 * cabr.registerRoute('\/api', {GET: 'read', POST: 'create'});
	 */
	registerRoute(route, permissions) {
		if (!route || !permissions) {
			return;
		}

		this.map[route] = this.map[route] || {};
		this.map[route].regExp = new RegExp(route, 'g');
		_.map(parsePermission(permissions, true), (p, m) => {
			m = m.toUpperCase();
			this.map[route][m] = this.map[route][m] || [];
			this.map[route][m] = _.concat(this.map[route][m], parsePermission(p));
		});
	}

	/**
	 * Return a middleware function checking access based on the given permissions.
	 * The rbac check function is called with the request as req param, the response as
	 * res param, any additional params can be feed with the params parameter.
	 *
	 * @param permissions {Array} Array of permissions or permission syntax strings that
	 * should be checked for this route.
	 * @param [params] Additional params to be passed to the attribute validation, beside req and res.
	 * @returns {Function} A middleware function calling next if the rbac check succeeded,
	 * calls the options unauthorizedHandler otherwise.
	 */
	guard(permissions, params) {
		return (req, res, next) => {
			params = _.defaults(params, {permissions, req, res});
			return Promise.resolve(this.options.userProvider.get(req))
				.then(user => this.rbac.check(user, permissions, params))
				.then(can => {
					if (can) {
						log('allow request for %s with permissions %s', req.originalUrl, permissions);
						return next();
					}

					log('deny request for %s with permissions %s', req.originalUrl, permissions);
					req.rbacFailed = permissions;
					return this.options.unauthorizedHandler(req, res, next);
				})
				.catch(next);
		};
	}
}

/**
 * @private
 * Get all needed permissions for a route
 */
function getPermissions(req, map) {
	return _(map)
		.filter(v => v.regExp.test(req.originalUrl))
		.map(v => v[req.method]).flatten().value();
}

/**
 * @private
 * Pre request handler
 * @param req {Object} The request object
 * @param res {Object} The response object
 * @param next {Function} The next middleware handler
 */
function pre(req, res, next) {
	log('handle request for %s', req.originalUrl);
	const config = getPermissions(req, this.map);
	req.cabr = true;

	if (config) {
		return this.guard(config)(req, res, next);
	}

	return next();
}

/**
 * @private
 * Post request handler, gets all attributes for the given user and calls the
 * attribute validation with the parameters req, res, body, permissions.
 * @param body {Object} The response body
 * @param req {Object} The request object
 * @param res {Object} The response object
 */
function post(json, req, res) {
	log('handle response for %s', req.originalUrl);
	const permissions = getPermissions(req, this.map);
	delete req.cabr;
	res.cabr = true;

	return new Promise((resolve, reject) => {
		Promise.resolve(this.options.userProvider.get(req))
		.then(user => {
			Promise.resolve(this.rbac.provider.getRoles(user))
			.then(roles => {
				Promise.mapSeries(_.keys(roles), r => Promise.resolve(this.rbac.provider.getAttributes(r)))
				.then(attrs => _.flatten(attrs))
				.reduce((body, attr) =>
					Promise.resolve(this.rbac.attributes.validate(attr, user, roles, {req, res, body, permissions}))
						.then(can => {
							if (!can) {
								log('deny in response handler for %s: %s', req.originalUrl, attr);
								req.rbacFailed = attr;
								return new Error('Unauthorized');
							}
							return body;
						}), json)
				.then(body => resolve(body))
				.catch(err => {
					log('error in response handling for %s: %s', req.originalUrl, err);
					this.options.unauthorizedHandler(req, res, reject);
				});
			});
		}).catch(err => {
			log('error while getting user for request on route %s: %s', req.originalUrl, err);
			reject(err);
		});
	});
}

/**
 * @private
 * Parse a given route permission configuration.
 * @param p {Object|Array|String} The permission object to parse
 * @param [extend] {Boolean} Applies only if p is not an object.
 * If set, the permission will be registered for all http methods.
 * @return {Array} The permission array
 */
function parsePermission(p, extend) {
	// check for an object first
	if (!_.isArray(p) && p === Object(p)) {
		return p;
	}

	// support simple permission strings or rbac expressions
	if (_.isString(p)) {
		p = [p];
	}

	// apply every http method
	if (extend && _.isArray(p)) {
		p = _.zipObject(
			httpMethods, _.map(httpMethods, _.constant(p))
		);
	}

	return p;
}

/**
 * @private
 * Unauthorized handler, simply send status 401 and call next
 * with an 'Unauthorized' error.
 * @param req {Object} The request object
 * @param res {Object} The response object
 * @param next {Function} The middleware handler
 * @return {*}
 */
function unauthorizedHandler(req, res, next) {
	res.sendStatus(401);
	const permission = req.rbacFailed ? req.rbacFailed : 'a permission';
	return next(new Error(`Unauthorized: Permission validation for ${req.originalUrl} failed for ${permission}`));
}

/**
 * Only exports the {@link module:cabr~CABR CABR class}.
 * @example
 * const CABR = require('cabr');
 */
module.exports = CABR;
