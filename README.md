# cabr

A module for handling RBAC-A in an express environment.

The CABR class provides rbac-a support for express/connect
applications. By configuring a route to permission mapping, the request is intercepted
based on the required permissions. Attributes defined in the RBAC service
will be called before and after all middleware to perform further role validation
or request/response filtering.

## Documentation
The API documentation can be found at [the github pages](https://michaelkrone.github.io/cabr).


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

// register the express app all request will be validated by
// the permissions defined in the route config
cabr.registerApp(app);

```