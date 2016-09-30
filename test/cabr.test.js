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
			guest: {
				permissions: ['create'],
				attributes: ['attributeDeny']
			},
			reader: {
				permissions: ['read'],
				inherited: ['guest'],
			},
			writer: {
				permissions: ['create'],
				inherited: ['reader'],
				attributes: ['attribute1', 'attribute2']
			},
			editor: {
				permissions: ['update'],
				inherited: ['reader']
			},
			someone: {
				permissions: ['update']
			}
		},
		users: {
			dummy: ['guest'],
			plummy: ['reader'],
			tummy: ['reader', 'writer'],
			yummy: ['writer', 'editor'],
			zummy: ['someone']
		}
	};

	t.context.map = {
		'.*': 'read',
	 	'^\\/pets$': 'create',
	 	'^\\/pets\\/cats$': ['create', 'update'],
		'^\\/pets\\/dogs$': {get: 'create', post: ['sniff', 'wuff']}
	};

	const provider = new RBAC.providers.JsonProvider(t.context.rules);
	t.context.rbac = new RBAC({provider});
	t.context.rbac.attributes.set(attributeDeny);
	t.context.rbac.attributes.set(attribute1);
	t.context.rbac.attributes.set(attribute2);

	const get = req => req.user;
	t.context.cabr = new CABR(t.context.rbac, {
		routes: t.context.map,
		userProvider: {get: (req) => Promise.resolve(req.user)}
	});

	function attribute1(user, role, params) {
		if (params.body) {
			params.body.seen1 = params.res.cabr;
		}
		return true;
	}

	function attribute2(user, role, params) {
		if (params.res.cabr) {
			params.body.seen2 = true;
		}
		return Promise.resolve(true);
	}

	function attributeDeny(user, role, params) {
		return false;
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
	const entry = t.context.cabr.map.find(r => r.route === '.*');
	httpMethods.map(m => t.truthy(entry[m.toUpperCase()]));
});

test('cabr adds permission arrays', t => {
	const entry = t.context.cabr.map.find(r => r.route === '^\\/pets\\/cats$');
	httpMethods.map(m => {
		m = m.toUpperCase();
		t.truthy(entry[m.toUpperCase()]);
		t.deepEqual(entry[m.toUpperCase()], ['create', 'update']);
	});
});

test('cabr adds permission objects with uppercased http methods', t => {
	const entry = t.context.cabr.map.find(r => r.route === '^\\/pets\\/dogs$');
	['GET', 'POST'].map(m => {
		const p = entry[m];
		const expected = _.isArray(p) ? p : [p];
		t.truthy(entry[m]);
		t.deepEqual(entry[m], expected);
	});
});

test('cabr provides a function to register a handler for a route', t => {
	t.true(typeof t.context.cabr.registerRoute === 'function');
	t.context.cabr.registerRoute('/new', 'wow!');
	const entry1 = t.context.cabr.map.find(r => r.route === '/new');
	t.truthy(entry1);
	t.deepEqual(entry1.POST, ['wow!']);

	t.context.cabr.registerRoute('/old', {gEt: 'boah!'});
	const entry2 = t.context.cabr.map.find(r => r.route === '/old');
	t.truthy(entry2);
	t.deepEqual(entry2.GET, ['boah!']);
});

test('cabr provides a function to register an express app', t => {
	t.true(typeof t.context.cabr.registerApp === 'function');
});

test('cabr denies access to a route', async t => {
	const app = express();
	app.all('*', setUserMiddleware('zummy'))

	t.context.cabr.registerApp(app)
		.use('/pets', (req, res) => res.status(200).json({ a: 'a' }));

	const res = await supertest(app).get('/pets');
	t.deepEqual(res.status, 401);
	t.false(res.body.hasOwnProperty('a'));
});

test('cabr allows access to a route', async t => {
	const app = express();
	app.all('*', setUserMiddleware('tummy'));

	t.context.cabr.registerApp(app)
		.use('/pets', (req, res) => res.status(200).json({ a: 'a' }));

	const res = await supertest(app).get('/pets');
	t.deepEqual(res.status, 200);
	t.true(res.body.hasOwnProperty('a'));
	t.deepEqual(res.body.a, 'a');
});

test('cabr performs response transformation', async t => {
	const app = express();
	app.all('*', setUserMiddleware('tummy'));

	t.context.cabr.registerApp(app)
		.use('/pets', (req, res) => res.status(200).json({ a: 'a' }));

	const res = await supertest(app).get('/pets');
	t.deepEqual(res.status, 200);
	t.true(typeof res.body === 'object');
	t.true(res.body.hasOwnProperty('a'));
	t.deepEqual(res.body.a, 'a');
	t.true(res.body.hasOwnProperty('seen1'));
	t.true(res.body.seen1);
	t.true(res.body.hasOwnProperty('seen2'));
	t.true(res.body.seen2);
});

test('cabr denies if an attribute denies', async t => {
	const app = express();
	app.all('*', setUserMiddleware('dummy'));

	t.context.cabr.registerApp(app)
		.use('/pets', (req, res) => res.status(200).json({ a: 'a' }));

	const res = await supertest(app).get('/pets');
	t.deepEqual(res.status, 401);
	t.false(res.body.hasOwnProperty('a'));
});