// The reset policy as an admin setting (reset.policy), and the protected-settings gate around it.
const { startServer, resetState, login, enrollUser, totpCode } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const ADMIN = { username: 'admin', password: 'Adm1nPass!' };

let server;
let api;
let db;
let settingsService;

before(async () => {
    server = await startServer();
    api = server.request;
    db = require('../../server/config/db');
    settingsService = require('../../server/services/settingsService');
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    await settingsService.refresh();
});

async function adminToken() {
    return (await login(api, ADMIN.username, ADMIN.password)).token;
}

describe('reset policy setting', () => {
    test('defaults to the .env value and is not stored', async () => {
        const res = await api('GET', '/api/admin/settings', undefined, await adminToken());
        assert.equal(res.status, 200);
        assert.equal(res.body.data.reset.policy, 'either');
        assert.equal(res.body.data.envDefaults.resetPolicy, 'either');
        assert.ok(!res.body.data.overrides.includes('reset.policy'));
    });

    test('an AD-group admin can change it with their password, and it applies at once', async () => {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const token = await adminToken();

        const saved = await api('PUT', '/api/admin/settings', {
            settings: { 'reset.policy': 'both' }, currentPassword: ADMIN.password,
        }, token);
        assert.equal(saved.status, 200, saved.body.message);
        assert.equal(saved.body.data.reset.policy, 'both');
        assert.ok(saved.body.data.overrides.includes('reset.policy'));

        const user = await api('POST', '/api/password/reset/verify-user', { username: 'jsmith' });
        assert.equal(user.body.data.policy, 'both');

        // The one-time code alone no longer counts
        const totp = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret) });
        assert.equal(totp.status, 400);
        assert.equal(totp.body.code, 'STEP_REQUIRED');

        const audit = await db.query("SELECT details FROM audit_log WHERE action = 'reset_policy_changed'");
        assert.deepEqual(audit.rows.map((r) => r.details), ['Reset policy: either -> both']);
    });

    test('a step token only works for the account it was issued to, whatever the letter case', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const { secret: otherSecret } = await enrollUser(api, 'mjones', 'Welcome1!');
        await api('PUT', '/api/admin/settings', {
            settings: { 'reset.policy': 'both' }, currentPassword: ADMIN.password,
        }, await adminToken());

        const step = await api('POST', '/api/password/reset/verify-questions', { username: 'JSmith', answers });
        assert.equal(step.status, 200, step.body.message);

        const misuse = await api('POST', '/api/password/reset/verify-totp', {
            username: 'mjones', code: totpCode(otherSecret), stepToken: step.body.data.stepToken,
        });
        assert.equal(misuse.body.code, 'STEP_REQUIRED');
    });

    test('invalid values, non-admins and missing or wrong passwords are refused', async () => {
        const token = await adminToken();
        const bad = await api('PUT', '/api/admin/settings', {
            settings: { 'reset.policy': 'weak' }, currentPassword: ADMIN.password,
        }, token);
        assert.equal(bad.status, 400);

        const missing = await api('PUT', '/api/admin/settings', { settings: { 'reset.policy': 'both' } }, token);
        assert.equal(missing.status, 401);
        assert.equal(missing.body.code, 'REAUTH_REQUIRED');

        const wrong = await api('PUT', '/api/admin/settings', {
            settings: { 'reset.policy': 'both' }, currentPassword: 'nope',
        }, token);
        assert.equal(wrong.status, 401);
        assert.equal(wrong.body.code, 'REAUTH_FAILED');

        const { token: userToken } = await login(api, 'jsmith', 'Passw0rd!');
        const user = await api('PUT', '/api/admin/settings', { settings: { 'reset.policy': 'both' } }, userToken);
        assert.equal(user.status, 403);

        assert.equal(settingsService.resetPolicy(), 'either');
    });

    test('a portal admin outside the AD admin group cannot change protected settings', async () => {
        const token = await adminToken();
        const { user } = await login(api, 'mjones', 'Welcome1!');
        assert.equal((await api('PUT', `/api/admin/users/${user.id}/admin`, { isAdmin: true }, token)).status, 200);
        const { token: portalAdmin } = await login(api, 'mjones', 'Welcome1!');

        const res = await api('PUT', '/api/admin/settings', {
            settings: { 'reset.policy': 'both' }, currentPassword: 'Welcome1!',
        }, portalAdmin);
        assert.equal(res.status, 403);
        assert.equal(res.body.code, 'AD_ADMIN_REQUIRED');

        // Settings that are not protected need neither
        const count = await api('PUT', '/api/admin/settings', { settings: { 'security.questionCount': '3' } }, portalAdmin);
        assert.equal(count.status, 200, count.body.message);
    });

    test('re-sending an unchanged protected value needs no password', async () => {
        const res = await api('PUT', '/api/admin/settings', {
            settings: { 'reset.policy': 'either', 'factors.totp': 'true' },
        }, await adminToken());
        assert.equal(res.status, 200, res.body.message);
    });
});
