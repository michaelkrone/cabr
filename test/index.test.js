import test from 'ava';
import CABR from '../index';

test('index exports the constructor function', t => {
	t.true(typeof CABR === 'function');
});
