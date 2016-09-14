import test from 'ava';
import * as _ from 'lodash';
import RBAC from 'rbac-a';
import express from 'express';
import supertest from 'supertest';

import httpMethods from '../lib/http-methods'
import CABR from '../lib/cabr';

function setUserMiddleware(username) {
	return (req, res, next) => {
		req.user = username;
		return next();
	}
}

test.beforeEach(t => {
	t.context.rules = {
		roles: {
			guest: {},
			reader: {
				permissions: ['read'],
				inherited: ['guest']
			},
			writer: {
				permissions: ['create'],
				inherited: ['reader'],
				attributes: ['attribute']
			},
			editor: {
				permissions: ['update'],
				inherited: ['reader']
			}
		},
		users: {
			dummy: ['guest'],
			plummy: ['reader'],
			tummy: ['reader', 'writer'],
			yummy: ['writer', 'editor']
		}
	};

	t.context.map = {
		'.*': 'read',
	 	'\/pets': 'create',
	 	'\/pets\/cats': ['create', 'update'],
		'\/pets\/dogs': {get: 'create', post: ['sniff', 'wuff']}
	};

	const provider = new RBAC.providers.JsonProvider(t.context.rules);
	t.context.rbac = new RBAC({provider});
	t.context.rbac.attributes.set(attribute);

	const get = req => req.user;
	t.context.cabr = new CABR(t.context.rbac, {
		routes: t.context.map,
		userProvider: {get: (req) => Promise.resolve(req.user)}
	});

	function attribute(user, role, param) {
		if (param.body) {
			param.body.seen = true;
		}
		return Promise.resolve(param.body);
	}
});

test('cabr exports the constructor function', t => {
	t.true(typeof CABR === 'function');
});

test('cabr constructor throws on invalid arguments', t => {
	t.throws(() => new CABR());
	t.throws(() => new CABR(() => 1));
	t.throws(() => new CABR({foo: 1}));
	t.throws(() => new CABR({rbac: {}}));
});

test('cabr creates a new instance with the correct arguments', t => {
	t.true(typeof t.context.cabr === 'object');
});

test('cabr adds a bunch of http methods to the request map if not specified in the permissions', t => {
	const testKeys = ['.*', '\/pets'];
	httpMethods.map(m => testKeys.map(k => {
		m = m.toUpperCase();
		t.truthy(t.context.cabr.map[k][m]);
		t.deepEqual(t.context.cabr.map[k][m], [t.context.map[k]]);
	}));
});

test('cabr adds permission arrays', t => {
	const key = '\/pets\/cats';
	httpMethods.map(m => {
		m = m.toUpperCase();
		t.truthy(t.context.cabr.map[key][m]);
		t.deepEqual(t.context.cabr.map[key][m], _.toArray(t.context.map[key]));
	});
});

test('cabr adds permission objects with uppercased http methods', t => {
	const key = '\/pets\/dogs';
	['GET', 'POST'].map(m => {
		const p = t.context.map[key][m.toLowerCase()];
		const expected = _.isArray(p) ? p : [p];
		t.truthy(t.context.cabr.map[key][m]);
		t.deepEqual(t.context.cabr.map[key][m], expected);
	});
});

test('cabr provides a function to register a handler for a route', t => {
	t.true(typeof t.context.cabr.registerRoute === 'function');
	t.context.cabr.registerRoute('/new', 'wow!');
	t.truthy(t.context.cabr.map['/new']);
	t.deepEqual(t.context.cabr.map['/new'].POST, ['wow!']);

	t.context.cabr.registerRoute('/old', {gEt: 'boah!'});
	t.truthy(t.context.cabr.map['/old']);
	t.deepEqual(t.context.cabr.map['/old'].GET, ['boah!']);
});

test('cabr provides a function to register an express app', t => {
	t.true(typeof t.context.cabr.registerApp === 'function');
});

test('cabr denies access to a route', async t => {
	const app = express();
	app.all('*', setUserMiddleware('dummy'))

	t.context.cabr.registerApp(app)
		.use('/pets', (req, res, next) => res.sendStatus(200));

	const res = await supertest(app).get('/pets');
	t.deepEqual(res.status, 401);
});

test('cabr allows access to a route', async t => {
	const app = express();
	app.all('*', setUserMiddleware('tummy'));

	t.context.cabr.registerApp(app)
		.use('/pets', (req, res, next) => res.sendStatus(200));

	const res = await supertest(app).get('/pets');
	t.deepEqual(res.status, 200);
});

test.skip('cabr performs response transformation', async t => {
	const app = express();
	app.all('*', setUserMiddleware('tummy'));

	t.context.cabr.registerApp(app)
		.use('/pets', (req, res) => res.status(200).json({ a: 'a' }));

	const res = await supertest(app).get('/pets');
	t.deepEqual(res.status, 200);
	t.deepEqual(res.body, true);
});