// The change and reset endpoints say which password policy rule a new password breaks.
const { startServer, resetState, login, enrollUser } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

let server;
let api;
let mockAd;
let policyService;

before(async () => {
    server = await startServer();
    api = server.request;
    mockAd = require('../../server/services/mockLdapService');
    policyService = require('../../server/services/passwordPolicyService');
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    policyService.resetCache();
});

async function change(token, currentPassword, newPassword) {
    return api('POST', '/api/password/change', { currentPassword, newPassword, confirmPassword: newPassword }, token);
}

async function resetToken(username, password) {
    const { answers } = await enrollUser(api, username, password);
    const answerFor = new Map(answers.map((a) => [a.questionId, a.answer]));
    const questions = await api('POST', '/api/password/reset/get-questions', { username });
    const verified = await api('POST', '/api/password/reset/verify-questions', {
        username, answers: questions.body.data.map((q) => ({ questionId: q.id, answer: answerFor.get(q.id) })),
    });
    return verified.body.data.resetToken;
}

describe('password policy explanations', () => {
    test('the rules endpoint reflects the domain policy', async () => {
        mockAd.setPasswordPolicy({ minPwdLength: '12', pwdHistoryLength: '24', minPwdAge: '-864000000000' });
        const { data } = (await api('GET', '/api/password/rules')).body;
        assert.deepEqual(data, { minLength: 12, complexity: true, historyCount: 24, minAgeDays: 1 });
    });

    test('a change lists every broken rule and changes nothing', async () => {
        mockAd.setPasswordPolicy({ minPwdLength: '12' });
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await change(token, 'Passw0rd!', 'jsmith2026');
        assert.equal(res.status, 400);
        assert.equal(res.body.code, 'PASSWORD_POLICY');
        assert.deepEqual(res.body.data.problems.map((p) => p.rule), ['length', 'complexity', 'username']);
        assert.match(res.body.message, /fix the points below/);
        // Still the old password
        await mockAd.authenticateUser('jsmith', 'Passw0rd!');
    });

    test('a part of the display name is named', async () => {
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await change(token, 'Passw0rd!', 'Smith-Garden-26');
        assert.equal(res.body.code, 'PASSWORD_POLICY');
        assert.match(res.body.message, /must not contain a part of your name \(Smith\)/);
    });

    test('a reused password is explained as history', async () => {
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        assert.equal((await change(token, 'Passw0rd!', 'Blue-Harbour-26')).status, 200);
        const { token: second } = await login(api, 'jsmith', 'Blue-Harbour-26');
        const res = await change(second, 'Blue-Harbour-26', 'Passw0rd!');
        assert.equal(res.status, 400);
        assert.deepEqual(res.body.data.problems.map((p) => p.rule), ['history']);
        assert.match(res.body.message, /one of your last 3 passwords/);
    });

    test('a change too soon after the last one says when it is possible', async () => {
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        assert.equal((await change(token, 'Passw0rd!', 'Blue-Harbour-26')).status, 200);
        mockAd.setPasswordPolicy({ minPwdAge: '-864000000000' });
        policyService.resetCache(); // the portal caches the domain policy for 15 minutes
        const { token: second } = await login(api, 'jsmith', 'Blue-Harbour-26');
        const res = await change(second, 'Blue-Harbour-26', 'Green-Meadow-27');
        assert.equal(res.status, 400);
        assert.deepEqual(res.body.data.problems.map((p) => p.rule), ['min-age']);
        assert.match(res.body.message, /You can change it again from/);
    });

    test('a reset reports the broken rule and keeps the reset token usable', async () => {
        const token = await resetToken('mjones', 'Welcome1!');
        const weak = await api('POST', '/api/password/reset/set-password', {
            resetToken: token, newPassword: 'mjones-weak', confirmPassword: 'mjones-weak',
        });
        assert.equal(weak.status, 400);
        assert.equal(weak.body.code, 'PASSWORD_POLICY');
        assert.ok(weak.body.data.problems.some((p) => p.rule === 'username'));

        const reused = await api('POST', '/api/password/reset/set-password', {
            resetToken: token, newPassword: 'Welcome1!', confirmPassword: 'Welcome1!',
        });
        assert.equal(reused.status, 400);
        assert.deepEqual(reused.body.data.problems.map((p) => p.rule), ['history']);

        const ok = await api('POST', '/api/password/reset/set-password', {
            resetToken: token, newPassword: 'Blue-Harbour-26', confirmPassword: 'Blue-Harbour-26',
        });
        assert.equal(ok.status, 200, ok.body.message);
    });
});
