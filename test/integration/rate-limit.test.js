// Runs with a low limiter threshold; node:test isolates each file in its own process.
process.env.RATE_LIMIT_MAX_OVERRIDE = '3';

const { startServer } = require('../helpers/setup');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

let server;
let api;

// Limiter counters live in memory for the whole file, so each test uses its own username.
before(async () => {
    server = await startServer();
    api = server.request;
});
after(() => server?.close());

test('login is limited per IP + username, case-insensitively', async () => {
    for (let i = 0; i < 3; i++) {
        assert.equal((await api('POST', '/api/auth/login', { username: 'mjones', password: 'bad' })).status, 401);
    }
    const blocked = await api('POST', '/api/auth/login', { username: 'mjones', password: 'Welcome1!' });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.body.success, false);
    assert.equal((await api('POST', '/api/auth/login', { username: 'MJones', password: 'bad' })).status, 429);

    // Other usernames are unaffected
    assert.equal((await api('POST', '/api/auth/login', { username: 'jsmith', password: 'Passw0rd!' })).status, 200);
});

test('reset verification endpoints are limited', async () => {
    for (let i = 0; i < 3; i++) {
        await api('POST', '/api/password/reset/verify-totp', { username: 'ghost1', code: '000000' });
    }
    const blocked = await api('POST', '/api/password/reset/verify-totp', { username: 'ghost1', code: '000000' });
    assert.equal(blocked.status, 429);
});

test('reset lookup endpoints are limited', async () => {
    for (let i = 0; i < 3; i++) {
        await api('POST', '/api/password/reset/verify-user', { username: 'ghost2' });
    }
    assert.equal((await api('POST', '/api/password/reset/verify-user', { username: 'ghost2' })).status, 429);
});
