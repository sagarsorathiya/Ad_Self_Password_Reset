// Audit fixes 2026-11-18: sessions, account state, first enrolment, letter case, AD write path, admin guards.
const { startServer, resetState, login, enrollUser } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

const NEW_PASSWORD = 'Brand-New-Pass1';
const ADMIN = { username: 'admin', password: 'Adm1nPass!' };

let server;
let api;
let db;
let mockAd;
let config;
let settingsService;

before(async () => {
    server = await startServer();
    api = server.request;
    db = require('../../server/config/db');
    mockAd = require('../../server/services/mockLdapService');
    config = require('../../server/config/default');
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

async function saveSetting(settings) {
    const res = await api('PUT', '/api/admin/settings', { settings, currentPassword: ADMIN.password }, await adminToken());
    assert.equal(res.status, 200, res.body.message);
    return res.body.data;
}

// Reset through the security questions (the test policy is 'either'); returns the set-password response
async function resetWithQuestions(typedName, answers, newPassword = NEW_PASSWORD) {
    const answerFor = new Map(answers.map((a) => [a.questionId, a.answer]));
    const questions = await api('POST', '/api/password/reset/get-questions', { username: typedName });
    const verified = await api('POST', '/api/password/reset/verify-questions', {
        username: typedName,
        answers: questions.body.data.map((q) => ({ questionId: q.id, answer: answerFor.get(q.id) })),
    });
    assert.equal(verified.status, 200, verified.body.message);
    return api('POST', '/api/password/reset/set-password', {
        resetToken: verified.body.data.resetToken, newPassword, confirmPassword: newPassword,
    });
}

function signAccess(payload) {
    return jwt.sign({ type: 'access', isAdmin: false, adGroupAdmin: false, ...payload }, config.jwt.secret, { expiresIn: '15m' });
}

describe('sessions', () => {
    test('a password change ends every session, access and refresh tokens alike', async () => {
        await enrollUser(api, 'jsmith', 'Passw0rd!');
        const other = await login(api, 'jsmith', 'Passw0rd!');

        const change = await api('POST', '/api/password/change', {
            currentPassword: 'Passw0rd!', newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        }, other.token);
        assert.equal(change.status, 200, change.body.message);

        const refresh = await api('POST', '/api/auth/refresh', { refreshToken: other.refreshToken });
        assert.equal(refresh.body.code, 'REFRESH_REVOKED');
        const status = await api('GET', '/api/enrollment/status', undefined, other.token);
        assert.equal(status.status, 401);
        assert.equal(status.body.code, 'SESSION_REVOKED');

        // Signing out still works with the revoked token
        assert.equal((await api('POST', '/api/auth/logout', {}, other.token)).status, 200);
    });

    test('a reset ends sessions opened before it', async () => {
        const { answers } = await enrollUser(api, 'mjones', 'Welcome1!');
        const before = await login(api, 'mjones', 'Welcome1!');

        const res = await resetWithQuestions('mjones', answers);
        assert.equal(res.status, 200, res.body.message);
        assert.equal((await api('GET', '/api/auth/me', undefined, before.token)).body.code, 'SESSION_REVOKED');
    });

    test('an access token from before tv existed asks the client to refresh', async () => {
        const { user } = await login(api, 'jsmith', 'Passw0rd!');
        const old = signAccess({ userId: user.id, username: 'jsmith' });
        const res = await api('GET', '/api/auth/me', undefined, old);
        assert.equal(res.status, 401);
        assert.equal(res.body.code, 'TOKEN_EXPIRED');
    });

    test('refresh refuses an account that AD has disabled, and audits it', async () => {
        const { refreshToken } = await login(api, 'jsmith', 'Passw0rd!');
        mockAd.setAttributes('jsmith', { userAccountControl: '514' });

        const res = await api('POST', '/api/auth/refresh', { refreshToken });
        assert.equal(res.status, 401);
        assert.equal(res.body.code, 'REFRESH_REVOKED');
        const audit = await db.query("SELECT details FROM audit_log WHERE action = 'session_revoked'");
        assert.deepEqual(audit.rows.map((r) => r.details), ['Account disabled in AD']);
    });
});

describe('first enrolment needs a recent sign-in', () => {
    test('an old session must confirm the password before setting up a factor', async () => {
        const { user } = await login(api, 'jsmith', 'Passw0rd!');
        const tv = (await db.query('SELECT token_version FROM users WHERE id = $1', [user.id])).rows[0].token_version;
        const stale = signAccess({ userId: user.id, username: 'jsmith', tv, authTime: Math.floor(Date.now() / 1000) - 20 * 60 });

        const refused = await api('POST', '/api/enrollment/totp/setup', {}, stale);
        assert.equal(refused.status, 401);
        assert.equal(refused.body.code, 'RECENT_AUTH_REQUIRED');

        const wrong = await api('POST', '/api/auth/reauth', { password: 'nope' }, stale);
        assert.equal(wrong.body.code, 'REAUTH_FAILED');

        const reauth = await api('POST', '/api/auth/reauth', { password: 'Passw0rd!' }, stale);
        assert.equal(reauth.status, 200, reauth.body.message);
        const setup = await api('POST', '/api/enrollment/totp/setup', {}, reauth.body.data.token);
        assert.equal(setup.status, 200, setup.body.message);
    });
});

describe('account state at sign-in and reset', () => {
    test('a lockout that has expired in AD no longer blocks sign-in', async () => {
        assert.equal((await api('POST', '/api/auth/login', { username: 'was.locked', password: 'Passw0rd!' })).status, 200);
        const locked = await api('POST', '/api/auth/login', { username: 'locked.user', password: 'Passw0rd!' });
        assert.equal(locked.status, 403);
        assert.match(locked.body.message, /locked out/);
    });

    test('an expired password sends the user to Forgot password', async () => {
        const res = await api('POST', '/api/auth/login', { username: 'expired.user', password: 'Passw0rd!' });
        assert.equal(res.status, 403);
        assert.equal(res.body.code, 'PASSWORD_EXPIRED');
    });

    test('a reset also unlocks the AD account', async () => {
        mockAd.setAttributes('locked.user', { lockoutTime: '0', 'msDS-User-Account-Control-Computed': '0' });
        const { answers } = await enrollUser(api, 'locked.user', 'Passw0rd!');
        mockAd.setAttributes('locked.user', { lockoutTime: '133000000000000000', 'msDS-User-Account-Control-Computed': '16' });

        const res = await resetWithQuestions('locked.user', answers);
        assert.equal(res.status, 200, res.body.message);
        assert.equal(res.body.data.unlocked, true);
        assert.equal((await api('POST', '/api/auth/login', { username: 'locked.user', password: NEW_PASSWORD })).status, 200);
        const audit = await db.query("SELECT success FROM audit_log WHERE action = 'account_unlock'");
        assert.deepEqual(audit.rows.map((r) => r.success), [true]);
    });

    test('administrator accounts are told up front that reset is not available', async () => {
        const { answers } = await enrollUser(api, ADMIN.username, ADMIN.password);
        const user = await api('POST', '/api/password/reset/verify-user', { username: ADMIN.username });
        assert.equal(user.status, 400);
        assert.equal(user.body.code, 'PROTECTED_ACCOUNT');

        // Even with a reset token, AD's refusal is explained, not reported as a 500
        mockAd.setProtectedResetRefused(true);
        const res = await resetWithQuestions(ADMIN.username, answers);
        assert.equal(res.status, 403);
        assert.equal(res.body.code, 'PROTECTED_ACCOUNT');
    });

    test('an account disabled after verification cannot finish the reset', async () => {
        const { answers } = await enrollUser(api, 'mjones', 'Welcome1!');
        const answerFor = new Map(answers.map((a) => [a.questionId, a.answer]));
        const questions = await api('POST', '/api/password/reset/get-questions', { username: 'mjones' });
        const verified = await api('POST', '/api/password/reset/verify-questions', {
            username: 'mjones', answers: questions.body.data.map((q) => ({ questionId: q.id, answer: answerFor.get(q.id) })),
        });
        mockAd.setAttributes('mjones', { userAccountControl: '514' });

        const res = await api('POST', '/api/password/reset/set-password', {
            resetToken: verified.body.data.resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        });
        assert.equal(res.status, 403);
        assert.match(res.body.message, /disabled/);
    });

    test('hiding account state gives every username the same answers', async () => {
        await saveSetting({ 'security.hideAccountState': 'true' });

        const ghost = await api('POST', '/api/password/reset/verify-user', { username: 'ghost' });
        assert.equal(ghost.status, 200);
        assert.equal(ghost.body.data.generic, true);
        assert.deepEqual(ghost.body.data.availableMethods, ['security_questions', 'totp']);

        for (const username of ['disabled.user', 'locked.user', 'expired.user']) {
            const res = await api('POST', '/api/auth/login', { username, password: 'Passw0rd!' });
            assert.equal(res.status, 401, username);
            assert.equal(res.body.message, 'Invalid username or password.');
        }
    });
});

describe('usernames in any letter case', () => {
    test('reset works with a different spelling and keeps one portal account', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        await login(api, 'JSMITH', 'Passw0rd!');
        const count = await db.query("SELECT COUNT(*)::int AS n FROM users WHERE LOWER(username) = 'jsmith'");
        assert.equal(count.rows[0].n, 1);

        const user = await api('POST', '/api/password/reset/verify-user', { username: 'JSmith' });
        assert.equal(user.status, 200, user.body.message);
        assert.equal(user.body.data.username, 'jsmith');

        const res = await resetWithQuestions('JSmith', answers);
        assert.equal(res.status, 200, res.body.message);
        const audit = await db.query("SELECT username FROM audit_log WHERE action = 'password_reset' AND success");
        assert.deepEqual(audit.rows.map((r) => r.username), ['jsmith']);
    });
});

describe('admin guards', () => {
    test('an admin cannot lock their own account', async () => {
        const { token, user } = await login(api, ADMIN.username, ADMIN.password);
        const res = await api('PUT', `/api/admin/users/${user.id}/lock`, { locked: true }, token);
        assert.equal(res.status, 400);
    });

    test('a question that users answered cannot be reworded', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const token = await adminToken();
        const list = (await api('GET', '/api/admin/questions', undefined, token)).body.data;
        const used = list.find((q) => q.id === answers[0].questionId);
        const unused = list.find((q) => !answers.some((a) => a.questionId === q.id));
        assert.equal(used.answer_count, 1);

        const reword = await api('PUT', `/api/admin/questions/${used.id}`, { questionText: 'Something else entirely?' }, token);
        assert.equal(reword.status, 409);
        const reorder = await api('PUT', `/api/admin/questions/${used.id}`, { questionText: used.question_text, sortOrder: 50 }, token);
        assert.equal(reorder.status, 200, reorder.body.message);
        const other = await api('PUT', `/api/admin/questions/${unused.id}`, { questionText: 'A brand new wording here?' }, token);
        assert.equal(other.status, 200, other.body.message);
    });

    test('the minimum password length comes from the settings', async () => {
        assert.deepEqual((await api('GET', '/api/password/rules')).body.data,
            { minLength: 8, complexity: true, historyCount: 3, minAgeDays: 0 });
        await saveSetting({ 'security.passwordMinLength': '12' });
        assert.equal((await api('GET', '/api/password/rules')).body.data.minLength, 12);

        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await api('POST', '/api/password/change', {
            currentPassword: 'Passw0rd!', newPassword: 'Short-Pa1', confirmPassword: 'Short-Pa1',
        }, token);
        assert.equal(res.status, 400);
        assert.match(res.body.message, /at least 12/);
    });

    test('the reset lockout follows the settings', async () => {
        await saveSetting({ 'security.lockoutAttempts': '3' });
        const { answers } = await enrollUser(api, 'mjones', 'Welcome1!');
        const wrong = answers.map((a) => ({ questionId: a.questionId, answer: 'wrong' }));
        for (let i = 0; i < 3; i++) {
            assert.equal((await api('POST', '/api/password/reset/verify-questions', { username: 'mjones', answers: wrong })).status, 400);
        }
        const locked = await api('POST', '/api/password/reset/verify-questions', { username: 'mjones', answers });
        assert.equal(locked.status, 429);
    });

    test('audit retention must be 0 or at least 30 days', async () => {
        const token = await adminToken();
        assert.equal((await api('PUT', '/api/admin/settings', { settings: { 'audit.retentionDays': '10' } }, token)).status, 400);
        assert.equal((await saveSetting({ 'audit.retentionDays': '90' })).audit.retentionDays, 90);
        assert.equal((await saveSetting({ 'audit.retentionDays': '0' })).audit.retentionDays, 0);
    });
});

describe('the SMS gateway URL is a secret', () => {
    test('a plain-text URL stored before is still used, then encrypted in place, and never returned', async () => {
        await db.query("INSERT INTO app_settings (key, value) VALUES ('sms.url', 'https://gw.example.test/send?key=s3cret')");
        await settingsService.refresh();
        assert.equal(settingsService.current().sms.url, 'https://gw.example.test/send?key=s3cret');

        const row = (await db.query("SELECT value FROM app_settings WHERE key = 'sms.url'")).rows[0];
        assert.doesNotMatch(row.value, /s3cret/);
        await settingsService.refresh();
        assert.equal(settingsService.current().sms.url, 'https://gw.example.test/send?key=s3cret');

        const shown = (await api('GET', '/api/admin/settings', undefined, await adminToken())).body.data;
        assert.equal(shown.sms.url, '********');
        assert.equal(shown.sms.urlHint.host, 'gw.example.test');
        assert.doesNotMatch(JSON.stringify(shown), /s3cret/);

        // Sending the placeholder back keeps the stored URL and needs no password
        const keep = await api('PUT', '/api/admin/settings', { settings: { 'sms.url': '********' } }, await adminToken());
        assert.equal(keep.status, 200, keep.body.message);
        assert.equal(settingsService.current().sms.url, 'https://gw.example.test/send?key=s3cret');
    });

    test('the portal server itself is refused as a gateway', async () => {
        const res = await api('PUT', '/api/admin/settings', {
            settings: { 'sms.url': 'http://127.0.0.1:9000/x' }, currentPassword: ADMIN.password,
        }, await adminToken());
        assert.equal(res.status, 400);
        assert.match(res.body.message, /not this server/);
    });
});
