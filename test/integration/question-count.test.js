// The number of security questions is an admin setting: new enrollments follow it, while users who enrolled
// under a larger count keep their answers and are still asked all of them at reset.
const { startServer, resetState, login, enrollUser } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

let server;
let api;
let settingsService;

before(async () => {
    server = await startServer();
    api = server.request;
    settingsService = require('../../server/services/settingsService');
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    await settingsService.refresh();
});

async function setCount(count) {
    const { token } = await login(api, 'admin', 'Adm1nPass!');
    const res = await api('PUT', '/api/admin/settings', { settings: { 'security.questionCount': String(count) } }, token);
    assert.equal(res.status, 200, res.body.message);
    assert.equal(res.body.data.security.questionCount, count);
}

async function questionsFor(username, token) {
    return (await api('GET', '/api/enrollment/questions', undefined, token)).body.data;
}

describe('security question count', () => {
    test('defaults to 3 and is reported to the enrollment page', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const status = (await api('GET', '/api/enrollment/status', undefined, token)).body.data;
        assert.equal(status.questionCount, 3);
    });

    test('only an admin can change it, and only within 2 to 5', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        assert.equal((await api('PUT', '/api/admin/settings',
            { settings: { 'security.questionCount': '2' } }, token)).status, 403);

        const admin = (await login(api, 'admin', 'Adm1nPass!')).token;
        for (const bad of ['1', '6', 'two', '']) {
            assert.equal((await api('PUT', '/api/admin/settings',
                { settings: { 'security.questionCount': bad } }, admin)).status, 400, `count ${bad}`);
        }
        assert.equal(settingsService.current().security.questionCount, 3);
    });

    test('with 2 configured, enrollment takes exactly 2 and reset asks for 2', async () => {
        await setCount(2);

        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const questions = await questionsFor('jsmith', token);

        // Three are now one too many
        const three = questions.slice(0, 3).map((q, i) => ({ questionId: q.id, answer: `Answer${i}` }));
        const tooMany = await api('POST', '/api/enrollment/security-questions', { answers: three }, token);
        assert.equal(tooMany.status, 400);
        assert.match(tooMany.body.message, /Exactly 2/);

        // A full enrollment now stores exactly two, and the reset flow asks for those two
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        assert.equal(answers.length, 2);

        const asked = (await api('POST', '/api/password/reset/get-questions', { username: 'jsmith' })).body.data;
        assert.equal(asked.length, 2);
        const verify = await api('POST', '/api/password/reset/verify-questions', { username: 'jsmith', answers });
        assert.equal(verify.status, 200, verify.body.message);
        assert.ok(verify.body.data.resetToken);
    });

    test('users enrolled with 3 keep them after the switch to 2', async () => {
        const { answers } = await enrollUser(api, 'mjones', 'Welcome1!');
        assert.equal(answers.length, 3);

        await setCount(2);

        // Still asked all three, and answering only two is refused
        const asked = (await api('POST', '/api/password/reset/get-questions', { username: 'mjones' })).body.data;
        assert.equal(asked.length, 3);

        const partial = await api('POST', '/api/password/reset/verify-questions', {
            username: 'mjones', answers: answers.slice(0, 2),
        });
        assert.equal(partial.status, 400);

        const full = await api('POST', '/api/password/reset/verify-questions', { username: 'mjones', answers });
        assert.equal(full.status, 200, full.body.message);
    });

    test('saving questions again moves such a user down to 2', async () => {
        await enrollUser(api, 'jsmith', 'Passw0rd!');
        await setCount(2);

        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const questions = await questionsFor('jsmith', token);
        const two = questions.slice(0, 2).map((q, i) => ({ questionId: q.id, answer: `Fresh${i}` }));

        // Changing existing answers needs the current password
        assert.equal((await api('POST', '/api/enrollment/security-questions', { answers: two }, token)).status, 401);
        const saved = await api('POST', '/api/enrollment/security-questions',
            { answers: two, currentPassword: 'Passw0rd!' }, token);
        assert.equal(saved.status, 200, saved.body.message);

        const mine = (await api('GET', '/api/enrollment/security-questions', undefined, token)).body.data;
        assert.equal(mine.length, 2);
        const asked = (await api('POST', '/api/password/reset/get-questions', { username: 'jsmith' })).body.data;
        assert.equal(asked.length, 2);
    });

    test('unknown users get decoy questions in the configured number', async () => {
        await setCount(2);
        const decoys = (await api('POST', '/api/password/reset/get-questions', { username: 'nosuchuser' })).body.data;
        assert.equal(decoys.length, 2);
    });
});
