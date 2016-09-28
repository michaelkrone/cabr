# cabr

[![Known Vulnerabilities](https://snyk.io/test/npm/cabr/badge.svg)](https://snyk.io/test/npm/cabr)

A module for handling RBAC-A in an express environment.

The CABR class provides rbac-a support for express/connect
applications. By configuring a route to permission mapping, the request is intercepted
based on the required permissions. Attributes defined in the RBAC service
will be called before and after all middleware to perform further role validation
or request/response filtering.

## Documentation
The API documentation can be found at [the github pages](https://michaelkrone.github.io/cabr).

## Installation
```bash
$ npm install --save cabr
```

## Example usage
```js
const express = require('express');
const rbac = require('rbac-a');
const CABR = require('cabr');
const app = express();

// init the rbac instance ...
const rbac = ...

const routes = {
	// every route, every HTTP method needs the awesome permission
	'.*': 'awesome',

	// every route, every HTTP method needs the 'awesome', yolo' and 'funky' permission
	'^\/funky': ['yolo', 'funky'],

	// every route, every HEAD request needs the 'clever' and 'smart' permission
	// plus the 'awesome' permission
	'.*': {HEAD: ['clever', 'smart']}, // or 'clever && smart'

	// every route, every COPY request needs the either the 'clever' or 'smart' permission
	// plus the 'awesome' permission
	'.': {COPY: 'clever || smart']},

	// ALL HTTP methods for '/pets' will be checked with the 'pets.read'
	// permission and 'awesome' permissions
	'\/pets': 'pets.read',

	// Custom config for '/cats', different HTTP methods
	// will apply different permissions
	'\/pets\/cats': {GET: 'pets.read', POST: 'cats.create', DELETE: ['pets.create', 'pets.delete']},
};

// init the cabr instance
const cabr = new CABR(rbac, {routes});


// use a custom user provider
const get = (req) => Promise.resolve(req.user);
cabr = new CABR(rbac, {routes, userProvider: {get}});

// register the express app - all request will be validated by
// the permissions defined in the route config
cabr.registerApp(app);

```

## A request/response loop
A request is first validated against all matching permissions and attributes. To get the roles
of the specific user, the `options.userProvider.get` method will be called with the current request
object to get the identifier the registered rbac.provider can be queried with to get the role
information for a user. Whut? Example:
```js
// in the rbac mapping
{
	...
	 "users": {
		"1": ["writer"],
		"2": ["admin"]
	}
}

// assume this returns 1 or 2
const userProvider = req => req.user._id;
```
Of course you can use any other logic in your providers. You might also return a promise, resolving the username.
If any permission validation fails, the `options.unauthorizedHandler` middleware will be called with the
failing permission attached to the request object as `rbacFailed`. The registered attribute functions of
the role will be called with the user/userId, the user role and an object consisting of the keys

- `req` - the current request object, req.cabr is set to true
- `res` - the current response object, res.cabr is undefined
- `permissions` - the permissions applied for this route

   If any additional params are passed as an object to the `guard` middleware, these parameters will be available
in the attribute validation function as well.

If any attribute function returns or resolves to a falsy value, the the `options.unauthorizedHandler` is called
with the `rbacFailed` property of the request object set to the failing attribute name.

After that, all registered middlewares are applied. Then, all attribute functions of a role are called again
with the user/userId, the user role and an object consisting of the keys

- `req` - the current request object, req.cabr is undefined
- `res` - the current response object, res.cabr is set to true
- `permissions` - the permissions applied for this route
- `body` - the response body, which may be mutated/filtered by the attribute functions

   Note that you should not dereference the request body, since this may cause errors. Note that this does only
   work for json responses, and if no response has been send already.

If any attribute validation fails, the `options.unauthorizedHandler` middleware will be called, with an error handler
passed as the next function. Otherwise the mutated json response is send.