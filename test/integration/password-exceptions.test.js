const { startServer, resetState, login, enrollUser, totpCode } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { matches } = require('../../server/services/passwordExceptionService');

let server;
let api;

before(async () => {
    server = await startServer();
    api = server.request;
});
after(() => server?.close());
beforeEach(() => resetState());

describe('password exception matching', () => {
    test('contains is case-insensitive and catches look-alikes', () => {
        assert.ok(matches('MyCompany2026!', 'company', 'contains'));
        assert.ok(matches('C0mp@ny#2026', 'company', 'contains'));
        assert.ok(matches('Welc0me1!', 'welcome', 'contains'));
        assert.ok(!matches('Str0ng!Horse', 'company', 'contains'));
    });

    test('exact only blocks the whole password', () => {
        assert.ok(matches('Summer@2026', 'summer@2026', 'exact'));
        assert.ok(!matches('Summer@2026x', 'summer@2026', 'exact'));
    });
});

describe('admin password exception management', () => {
    test('non-admins are forbidden', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        assert.equal((await api('GET', '/api/admin/password-exceptions', undefined, token)).status, 403);
        assert.equal((await api('POST', '/api/admin/password-exceptions', { term: 'company' }, token)).status, 403);
    });

    test('add, validate, reject duplicates, update and delete', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');

        assert.equal((await api('POST', '/api/admin/password-exceptions', { term: 'ab' }, token)).status, 400);
        assert.equal((await api('POST', '/api/admin/password-exceptions', { term: 'company', matchType: 'regex' }, token)).status, 400);

        const added = await api('POST', '/api/admin/password-exceptions', { term: 'Company' }, token);
        assert.equal(added.status, 201);
        assert.equal(added.body.data.match_type, 'contains');
        const id = added.body.data.id;

        assert.equal((await api('POST', '/api/admin/password-exceptions', { term: 'COMPANY' }, token)).status, 409);

        const updated = await api('PUT', `/api/admin/password-exceptions/${id}`, { term: 'corp', matchType: 'exact', isActive: false }, token);
        assert.equal(updated.status, 200);
        assert.equal(updated.body.data.term, 'corp');
        assert.equal(updated.body.data.is_active, false);

        assert.equal((await api('DELETE', `/api/admin/password-exceptions/${id}`, undefined, token)).status, 200);
        assert.equal((await api('DELETE', `/api/admin/password-exceptions/${id}`, undefined, token)).status, 404);
        assert.equal((await api('GET', '/api/admin/password-exceptions', undefined, token)).body.data.length, 0);
    });
});

describe('enforcement', () => {
    async function addException(term, matchType = 'contains') {
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        const res = await api('POST', '/api/admin/password-exceptions', { term, matchType }, token);
        assert.equal(res.status, 201);
        return { token, id: res.body.data.id };
    }

    test('password change rejects blocked words; inactive entries are ignored', async () => {
        const { token: adminToken, id } = await addException('company');
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const body = { currentPassword: 'Passw0rd!', newPassword: 'MyC0mpany#99', confirmPassword: 'MyC0mpany#99' };

        const blocked = await api('POST', '/api/password/change', body, token);
        assert.equal(blocked.status, 400);
        assert.match(blocked.body.message, /company/);

        await api('PUT', `/api/admin/password-exceptions/${id}`, { isActive: false }, adminToken);
        assert.equal((await api('POST', '/api/password/change', body, token)).status, 200);
    });

    test('password reset rejects blocked passwords without consuming the reset token', async () => {
        await addException('Summer@2026', 'exact');
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const verify = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30) });
        const { resetToken } = verify.body.data;

        const blocked = await api('POST', '/api/password/reset/set-password',
            { resetToken, newPassword: 'summer@2026', confirmPassword: 'summer@2026' });
        assert.equal(blocked.status, 400);

        const ok = await api('POST', '/api/password/reset/set-password',
            { resetToken, newPassword: 'Summer@2026-x', confirmPassword: 'Summer@2026-x' });
        assert.equal(ok.status, 200);
    });
});
