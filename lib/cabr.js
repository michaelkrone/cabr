/**
 * @module module:cabr
 * @description
 * The cabr module, which holds the CABR class.
 *
 * <pre>$ <kbd>NODE_DEBUG=cabr</kbd></pre>
 *
 * The {@link module:cabr~CABR CABR class} provides rbac-a support for express/connect
 * applications. By configuring a route to permission mapping, the request is intercepted
 * based on the required permissions. Attributes defined in the RBAC service
 * will be called before and after all middleware to perform further role validation
 * or request/response filtering.
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
	 * @param [options.provider] {Object} An RBAC-A provider which get method will be called with the current
	 * request to determine the current user. Defaults to the provider of the passed rbac instance.
	 * @param [options.routes] {Object} An object of regular expression strings mapped to a string or array of
	 * strings. See the {@link https://github.com/yanickrochon/rbac-a#grouped-permissions RBAC-A Grouped permissions syntax}
	 * for examples of valid permission configurations. The keys are used as regular expressions to determine if
	 * a route configuration applies for the current request.
	 * @param [options.userProvider] {Object} Provides an optional userProvider which get method will be called with the request
	 * object.
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
	 * 	// every route, every HTTP method needs the awesome and funky permission
	 *	'^\/funky': ['awesome', 'funky'],
	 *
	 *	// every route, every HEAD request needs the 'clever' and 'smart' permission
	 *	'.*': {HEAD: ['clever', 'smart']}, // or 'clever && smart'
	 *
	 *	// ALL HTTP methods for '/pets' will be checked with the 'pets.read' permission
	 *	'\/pets': 'pets.read',
	 *
	 *	// Custom config for '/cats', different HTTP methods
	 *	// will apply different permissions
	 *	'\/pets\/cats': {GET: 'pets.read', POST: 'cats.create', DELETE: ['pets.create', 'pets.delete']},
	 *
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

		this.options = Object.assign({}, defaultOptions, options || {});
		// setup the route mapping with the initial options map
		_.map(this.options.routes, (v, k) => this.registerRoute(k, v));
	}

	/**
	 * Register an {@link http://expressjs.com/en/4x.html#app express app}
	 * on this CABR instance. All mapped requests will be validated with the configured
	 * RBAC-A permissions. For all configured attributes of a request/response, the
	 * RBAC-A attribute function will be called with request and response for attributes configured
	 * as pre hanlders and request, respNODE_DEBUG=cabr onse and body for after filters, after all other middleware
	 * has been called. This method must be called before any route handling middleware is
	 * registered that modifies the response body!
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
	 * Add a route configuration at runtime.CABR supports dynamically building the route
	 * configuration.
	 * @param route {String} String used as a regular expression. The route the permissions should be applied to
	 * @param methods {String[]|String} Array of strings of HTTP method names or a single method
	 * as a string, '*' servers as a wildcard for all HTTP methods
	 * @param permissions {Array[]|Array|String}
	 * {@link https://github.com/yanickrochon/rbac-a#grouped-permissions RBAC-A Grouped permissions syntax}
	 * compatible object
	 * @example
	 * cabr.registerRoute('/api', {GET: 'read', POST: 'create'});
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
	 * @param permissions {Array} Array of permissions that should be checked
	 * @param [params] Additional params to be applied to the attribute validation
	 * @returns {Function} A middleware function calling next if the rbac check succeeded,
	 * calls the options unauthorizedHandler otherwise.
	 */
	guard(permissions, params) {
		return (req, res, next) => {
			params = _.assign(params || {}, {req, res});
			return Promise.resolve(this.options.userProvider.get(req))
				.then(user => this.rbac.check(user, permissions, {req, res}))
				.then(can => {
					if (can) {
						log('allow request for %s', req.originalUrl);
						return next();
					}

					log('deny request for %s', req.originalUrl);
					return this.options.unauthorizedHandler(req, res, next);
				})
				.catch(next);
		};
	}
}

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
 * Post request handler
 * @param body {Object} The response body
 * @param req {Object} The request object
 * @param res {Object} The response object
 */
function post(body, req, res) {
	log('handle response for %s', req.originalUrl);
	const config = getPermissions(req, this.map);
	res.cabr = true;

	return Promise.resolve(this.options.userProvider.get(req))
		.then(user => {
			Promise.resolve(this.rbac.provider.getRoles(user))
				.then(roles => _.keys(roles))
				.then(roles => {
					Promise.mapSeries(roles, r => this.rbac.provider.getAttributes(r))
						.then(attrs => _.flatten(attrs))
						.mapSeries(a => this.rbac.attributes.validate(a, user, roles, {req, res, body}))
					})
					.then(() => body);
				})




		.catch(err => {
			log('error in response handling for %s: %s', req.originalUrl, err);
			return body;
		});

	// return new Promise((resolve, reject) => {
	// 	this.guard(config, {body})(req, res, () => resolve(body))
	// 	.catch(err => {
	// 		log('error in response handling for %s: %s', req.originalUrl, err);
	// 		reject(err);
	// 	});
	// });
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
	return next(new Error('Unauthorized'));
}

/**
 * Only exports the {@link module:cabr~CABR CABR class}.
 * @example
 * const CABR = require('cabr');
 */
module.exports = CABR;
