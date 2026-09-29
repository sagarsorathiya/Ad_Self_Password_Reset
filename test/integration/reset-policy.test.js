const { startServer, resetState, enrollUser, totpCode, login } = require('../helpers/setup');
const { test, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const config = require('../../server/config/default');

let server;
let api;

before(async () => {
    server = await startServer();
    api = server.request;
});
after(() => server?.close());
beforeEach(() => resetState());
afterEach(() => { config.reset.policy = 'either'; });

async function answerQuestions(username, answers) {
    const qs = (await api('POST', '/api/password/reset/get-questions', { username })).body.data;
    const byId = new Map(answers.map((a) => [a.questionId, a.answer]));
    return api('POST', '/api/password/reset/verify-questions', {
        username,
        answers: qs.map((q) => ({ questionId: q.id, answer: byId.get(q.id) })),
    });
}

const NEW_PASSWORD = 'Brand-New-Pass1';

test("'both': questions alone never yield a reset token", async () => {
    config.reset.policy = 'both';
    const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');

    const user = await api('POST', '/api/password/reset/verify-user', { username: 'jsmith' });
    assert.equal(user.body.data.policy, 'both');

    const step1 = await answerQuestions('jsmith', answers);
    assert.equal(step1.status, 200);
    assert.equal(step1.body.data.resetToken, undefined);
    assert.ok(step1.body.data.stepToken);
});

test("'both': TOTP without a valid step token is rejected", async () => {
    config.reset.policy = 'both';
    const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');

    const none = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30) });
    assert.equal(none.status, 400);
    assert.equal(none.body.code, 'STEP_REQUIRED');

    const jwt = require('jsonwebtoken');
    const forged = jwt.sign({ type: 'reset_step', userId: 1, username: 'jsmith' }, 'wrong-secret');
    const bad = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30), stepToken: forged });
    assert.equal(bad.status, 400);
});

test("'both': step token is bound to the user who answered", async () => {
    config.reset.policy = 'both';
    const js = await enrollUser(api, 'jsmith', 'Passw0rd!');
    const mj = await enrollUser(api, 'mjones', 'Welcome1!');

    const step1 = await answerQuestions('jsmith', js.answers);
    const cross = await api('POST', '/api/password/reset/verify-totp', {
        username: 'mjones', code: totpCode(mj.secret, 30), stepToken: step1.body.data.stepToken,
    });
    assert.equal(cross.status, 400);
});

test("'both': questions + TOTP completes the reset", async () => {
    config.reset.policy = 'both';
    const { answers, secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');

    const step1 = await answerQuestions('jsmith', answers);
    const step2 = await api('POST', '/api/password/reset/verify-totp', {
        username: 'jsmith', code: totpCode(secret, 30), stepToken: step1.body.data.stepToken,
    });
    assert.equal(step2.status, 200, step2.body.message);

    const set = await api('POST', '/api/password/reset/set-password', {
        resetToken: step2.body.data.resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
    });
    assert.equal(set.status, 200);
    await login(api, 'jsmith', NEW_PASSWORD);

    const db = require('../../server/config/db');
    const audit = await db.query("SELECT method FROM audit_log WHERE action = 'password_reset' AND success");
    assert.deepEqual(audit.rows, [{ method: 'security_questions+totp' }]);
});

test("'both': the step token cannot be used as a session or a reset token", async () => {
    config.reset.policy = 'both';
    const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
    const { stepToken } = (await answerQuestions('jsmith', answers)).body.data;

    assert.equal((await api('GET', '/api/auth/me', undefined, stepToken)).status, 401);
    const set = await api('POST', '/api/password/reset/set-password', {
        resetToken: stepToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
    });
    assert.equal(set.status, 400);
});

test("'totp_only': questions are refused, TOTP alone works", async () => {
    config.reset.policy = 'totp_only';
    const { answers, secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');

    const user = await api('POST', '/api/password/reset/verify-user', { username: 'jsmith' });
    assert.deepEqual(user.body.data.availableMethods, ['totp']);

    const sq = await answerQuestions('jsmith', answers);
    assert.equal(sq.status, 400);

    const totp = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30) });
    assert.equal(totp.status, 200);
    assert.ok(totp.body.data.resetToken);
});
