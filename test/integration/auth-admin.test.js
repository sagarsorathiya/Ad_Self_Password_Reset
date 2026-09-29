const { startServer, resetState, login, enrollUser } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

let server;
let api;

before(async () => {
    server = await startServer();
    api = server.request;
});
after(() => server?.close());
beforeEach(() => resetState());

describe('authentication', () => {
    test('login issues access + refresh tokens and /me works', async () => {
        const data = await login(api, 'jsmith', 'Passw0rd!');
        assert.ok(data.token && data.refreshToken);
        assert.equal(data.user.isAdmin, false);

        const me = await api('GET', '/api/auth/me', undefined, data.token);
        assert.equal(me.status, 200);
        assert.equal(me.body.data.username, 'jsmith');
    });

    test('invalid, disabled and locked-out accounts are rejected', async () => {
        assert.equal((await api('POST', '/api/auth/login', { username: 'jsmith', password: 'bad' })).status, 401);
        assert.equal((await api('POST', '/api/auth/login', { username: 'ghost', password: 'bad' })).status, 401);
        assert.equal((await api('POST', '/api/auth/login', { username: 'disabled.user', password: 'Passw0rd!' })).status, 403);
        assert.equal((await api('POST', '/api/auth/login', { username: 'locked.user', password: 'Passw0rd!' })).status, 403);
    });

    test('unknown and wrong-password logins return the same message', async () => {
        const a = await api('POST', '/api/auth/login', { username: 'jsmith', password: 'bad' });
        const b = await api('POST', '/api/auth/login', { username: 'ghost', password: 'bad' });
        assert.equal(a.body.message, b.body.message);
    });

    test('refresh token issues a new access token; access token cannot refresh', async () => {
        const { token, refreshToken } = await login(api, 'jsmith', 'Passw0rd!');
        const ok = await api('POST', '/api/auth/refresh', { refreshToken });
        assert.equal(ok.status, 200);
        assert.ok(ok.body.data.token);

        assert.equal((await api('POST', '/api/auth/refresh', { refreshToken: token })).status, 401);
    });

    test('logout revokes outstanding refresh tokens', async () => {
        const { token, refreshToken } = await login(api, 'jsmith', 'Passw0rd!');
        assert.equal((await api('POST', '/api/auth/logout', {}, token)).status, 200);
        const res = await api('POST', '/api/auth/refresh', { refreshToken });
        assert.equal(res.status, 401);
        assert.equal(res.body.code, 'REFRESH_REVOKED');
    });

    test('refresh and reset tokens cannot be used as a session', async () => {
        const { enrollUser: enroll, totpCode } = require('../helpers/setup');
        const { refreshToken } = await login(api, 'jsmith', 'Passw0rd!');
        const { secret } = await enroll(api, 'jsmith', 'Passw0rd!');
        const reset = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30) });
        const resetToken = reset.body.data.resetToken;

        for (const bearer of [refreshToken, resetToken]) {
            assert.equal((await api('GET', '/api/auth/me', undefined, bearer)).status, 401);
            assert.equal((await api('POST', '/api/enrollment/totp/setup', {}, bearer)).status, 401);
        }
    });

    test('unknown usernames (often mistyped passwords) are never stored in the audit log', async () => {
        await api('POST', '/api/auth/login', { username: 'MySecretP@ss1', password: 'x' });
        const db = require('../../server/config/db');
        const rows = (await db.query("SELECT username FROM audit_log WHERE username ILIKE '%secret%'")).rows;
        assert.equal(rows.length, 0);
    });

    test('malformed JSON is rejected without echoing the body', async () => {
        const res = await fetch(`${server.baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{"username":"jsmith","password":"Passw0rd!"',
        });
        const text = await res.text();
        assert.equal(res.status, 400);
        assert.ok(!text.includes('Passw0rd'));
    });

    test('API responses are not cacheable', async () => {
        const res = await fetch(`${server.baseUrl}/api/auth/login`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
        });
        assert.equal(res.headers.get('cache-control'), 'no-store');
    });

    test('protected routes require a valid bearer token', async () => {
        assert.equal((await api('GET', '/api/auth/me')).status, 401);
        assert.equal((await api('GET', '/api/auth/me', undefined, 'not.a.jwt')).status, 401);
        assert.equal((await api('GET', '/api/enrollment/status')).status, 401);
    });

    test('logins are written to the audit log', async () => {
        await login(api, 'jsmith', 'Passw0rd!');
        await api('POST', '/api/auth/login', { username: 'jsmith', password: 'bad' });
        const db = require('../../server/config/db');
        const rows = (await db.query("SELECT success FROM audit_log WHERE action = 'login' ORDER BY id")).rows;
        assert.deepEqual(rows.map((r) => r.success), [true, false]);
    });
});

describe('admin', () => {
    test('non-admins are forbidden', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        for (const url of ['/api/admin/users', '/api/admin/stats', '/api/admin/audit-log', '/api/admin/questions']) {
            assert.equal((await api('GET', url, undefined, token)).status, 403, url);
        }
    });

    test('stats, user search and filters', async () => {
        await enrollUser(api, 'jsmith', 'Passw0rd!');
        await login(api, 'mjones', 'Welcome1!');
        const { token } = await login(api, 'admin', 'Adm1nPass!');

        const stats = (await api('GET', '/api/admin/stats', undefined, token)).body.data;
        assert.equal(Number(stats.total_users), 3);
        assert.equal(Number(stats.enrolled_users), 1);

        const enrolled = (await api('GET', '/api/admin/users?filter=enrolled', undefined, token)).body.data;
        assert.deepEqual(enrolled.users.map((u) => u.username), ['jsmith']);

        const search = (await api('GET', '/api/admin/users?search=mary', undefined, token)).body.data;
        assert.deepEqual(search.users.map((u) => u.username), ['mjones']);
    });

    test('search input is treated as data, not SQL', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        const res = await api('GET', `/api/admin/users?search=${encodeURIComponent("' OR 1=1 --")}`, undefined, token);
        assert.equal(res.status, 200);
        assert.equal(res.body.data.users.length, 0);
    });

    test('lock blocks login and reset; unlock restores access', async () => {
        await enrollUser(api, 'jsmith', 'Passw0rd!');
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        const users = (await api('GET', '/api/admin/users?search=jsmith', undefined, token)).body.data.users;
        const id = users[0].id;
        const { refreshToken } = await login(api, 'jsmith', 'Passw0rd!');

        assert.equal((await api('PUT', `/api/admin/users/${id}/lock`, { locked: true }, token)).status, 200);
        assert.equal((await api('POST', '/api/auth/refresh', { refreshToken })).status, 401);
        assert.equal((await api('POST', '/api/auth/login', { username: 'jsmith', password: 'Passw0rd!' })).status, 403);
        assert.equal((await api('POST', '/api/password/reset/verify-user', { username: 'jsmith' })).status, 403);

        assert.equal((await api('PUT', `/api/admin/users/${id}/lock`, { locked: 'yes' }, token)).status, 400);
        assert.equal((await api('PUT', `/api/admin/users/${id}/lock`, { locked: false }, token)).status, 200);
        await login(api, 'jsmith', 'Passw0rd!');
    });

    test('reset enrollment clears recovery data', async () => {
        await enrollUser(api, 'jsmith', 'Passw0rd!');
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        const id = (await api('GET', '/api/admin/users?search=jsmith', undefined, token)).body.data.users[0].id;

        assert.equal((await api('PUT', `/api/admin/users/${id}/reset-enrollment`, {}, token)).status, 200);

        const user = await login(api, 'jsmith', 'Passw0rd!');
        assert.equal(user.user.isEnrolled, false);
        assert.equal((await api('POST', '/api/password/reset/verify-user', { username: 'jsmith' })).status, 400);
    });

    test('question management: add, validate, deactivate', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');

        assert.equal((await api('POST', '/api/admin/questions', { questionText: 'short' }, token)).status, 400);

        const added = await api('POST', '/api/admin/questions', { questionText: 'What was your first phone model?', sortOrder: 99 }, token);
        assert.equal(added.status, 201);
        const id = added.body.data.id;

        assert.equal((await api('PUT', `/api/admin/questions/${id}`, { isActive: false }, token)).status, 200);

        const userToken = (await login(api, 'jsmith', 'Passw0rd!')).token;
        const active = (await api('GET', '/api/enrollment/questions', undefined, userToken)).body.data;
        assert.ok(!active.some((q) => q.id === id));
    });

    test('audit log filters by action', async () => {
        await login(api, 'jsmith', 'Passw0rd!');
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        const logs = (await api('GET', '/api/admin/audit-log?action=login&username=jsmith', undefined, token)).body.data.logs;
        assert.equal(logs.length, 1);
        assert.equal(logs[0].username, 'jsmith');
    });
});
