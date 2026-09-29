const { startServer, resetState, login, enrollUser, totpCode } = require('../helpers/setup');
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

const NEW_PASSWORD = 'Brand-New-Pass1';

async function verifyWithQuestions(username, answers) {
    const questions = await api('POST', '/api/password/reset/get-questions', { username });
    assert.equal(questions.status, 200);
    const answerFor = new Map(answers.map((a) => [a.questionId, a.answer]));
    return api('POST', '/api/password/reset/verify-questions', {
        username,
        answers: questions.body.data.map((q) => ({ questionId: q.id, answer: answerFor.get(q.id) })),
    });
}

describe('enrollment', () => {
    test('new user starts unenrolled and becomes enrolled after both steps', async () => {
        const first = await login(api, 'jsmith', 'Passw0rd!');
        assert.equal(first.user.isEnrolled, false);

        await enrollUser(api, 'jsmith', 'Passw0rd!');

        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const status = await api('GET', '/api/enrollment/status', undefined, token);
        assert.deepEqual(
            { e: status.body.data.isEnrolled, sq: status.body.data.securityQuestionsSet, t: status.body.data.totpEnabled },
            { e: true, sq: true, t: true }
        );
    });

    test('rejects duplicate questions and short answers', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const dup = await api('POST', '/api/enrollment/security-questions', {
            answers: [1, 1, 2].map((questionId) => ({ questionId, answer: 'valid' })),
        }, token);
        assert.equal(dup.status, 400);

        const short = await api('POST', '/api/enrollment/security-questions', {
            answers: [1, 2, 3].map((questionId) => ({ questionId, answer: 'x' })),
        }, token);
        assert.equal(short.status, 400);
    });

    test('rejects an invalid TOTP code during setup', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const setup = await api('POST', '/api/enrollment/totp/setup', {}, token);
        const wrong = totpCode(setup.body.data.secret, -300);
        const res = await api('POST', '/api/enrollment/totp/verify', { code: wrong }, token);
        assert.equal(res.status, 400);
    });

    test('stores TOTP secret encrypted and answers hashed', async () => {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const db = require('../../server/config/db');
        const user = (await db.query('SELECT id, totp_secret FROM users WHERE username = $1', ['jsmith'])).rows[0];
        assert.ok(!user.totp_secret.includes(secret));
        assert.match(user.totp_secret, /^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);

        const hashes = (await db.query('SELECT answer_hash FROM user_security_answers WHERE user_id = $1', [user.id])).rows;
        assert.equal(hashes.length, 3);
        hashes.forEach((h) => assert.match(h.answer_hash, /^\$2[aby]\$12\$/));
    });
});

describe('security settings (after enrollment)', () => {
    test('lists current questions without answers; blank answers keep existing ones', async () => {
        const { token, answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');

        const mine = await api('GET', '/api/enrollment/security-questions', undefined, token);
        assert.deepEqual(mine.body.data.map((q) => q.questionId), answers.map((a) => a.questionId));
        assert.ok(mine.body.data.every((q) => !('answer' in q) && !('answer_hash' in q)));

        // Keep answers 1 and 2, change answer 3
        const update = await api('POST', '/api/enrollment/security-questions', {
            currentPassword: 'Passw0rd!',
            answers: [
                { questionId: answers[0].questionId, answer: '' },
                { questionId: answers[1].questionId, answer: '' },
                { questionId: answers[2].questionId, answer: 'NewAnswer' },
            ],
        }, token);
        assert.equal(update.status, 200);

        const updated = [answers[0], answers[1], { ...answers[2], answer: 'newanswer' }];
        assert.equal((await verifyWithQuestions('jsmith', updated)).status, 200);
    });

    test('blank answer is rejected for a newly chosen question', async () => {
        const { token, answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await api('POST', '/api/enrollment/security-questions', {
            currentPassword: 'Passw0rd!',
            answers: [
                { questionId: answers[0].questionId, answer: '' },
                { questionId: answers[1].questionId, answer: '' },
                { questionId: 10, answer: '' },
            ],
        }, token);
        assert.equal(res.status, 400);
    });

    test('changing existing factors requires the current password', async () => {
        const { token, answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const body = { answers: answers.map((a) => ({ ...a, answer: 'attacker' })) };

        const missing = await api('POST', '/api/enrollment/security-questions', body, token);
        assert.equal(missing.status, 401);
        assert.equal(missing.body.code, 'REAUTH_REQUIRED');

        const wrong = await api('POST', '/api/enrollment/security-questions', { ...body, currentPassword: 'nope' }, token);
        assert.equal(wrong.status, 401);
        assert.equal(wrong.body.code, 'REAUTH_FAILED');

        assert.equal((await api('POST', '/api/enrollment/totp/setup', {}, token)).status, 401);
        assert.equal((await api('POST', '/api/enrollment/totp/setup', { currentPassword: 'nope' }, token)).status, 401);

        // Original answers still valid
        assert.equal((await verifyWithQuestions('jsmith', answers)).status, 200);
    });

    test('replacing the authenticator keeps the old device until the new one is verified', async () => {
        const { token, secret: oldSecret } = await enrollUser(api, 'jsmith', 'Passw0rd!');

        const setup = await api('POST', '/api/enrollment/totp/setup', { currentPassword: 'Passw0rd!' }, token);
        const newSecret = setup.body.data.secret;

        // Abandoned setup: old device still works for reset, account stays enrolled
        const status = await api('GET', '/api/enrollment/status', undefined, token);
        assert.equal(status.body.data.isEnrolled, true);
        const oldWorks = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(oldSecret, 30) });
        assert.equal(oldWorks.status, 200);

        const verify = await api('POST', '/api/enrollment/totp/verify', { code: totpCode(newSecret, -30) }, token);
        assert.equal(verify.status, 200, verify.body.message);

        const oldFails = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(oldSecret, 30) });
        assert.equal(oldFails.status, 400);
        const newWorks = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(newSecret, 30) });
        assert.equal(newWorks.status, 200);
    });
});

describe('password reset via security questions', () => {
    test('full flow: verify user → answers → set password → login with new password', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');

        const user = await api('POST', '/api/password/reset/verify-user', { username: 'jsmith' });
        assert.equal(user.status, 200);
        assert.deepEqual(user.body.data.availableMethods.sort(), ['security_questions', 'totp']);

        // Answers are case- and whitespace-insensitive
        const verified = await verifyWithQuestions('jsmith', answers.map((a) => ({ ...a, answer: `  ${a.answer.toUpperCase()} ` })));
        assert.equal(verified.status, 200);
        const { resetToken } = verified.body.data;

        const set = await api('POST', '/api/password/reset/set-password', {
            resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        });
        assert.equal(set.status, 200, set.body.message);

        await login(api, 'jsmith', NEW_PASSWORD);
        const old = await api('POST', '/api/auth/login', { username: 'jsmith', password: 'Passw0rd!' });
        assert.equal(old.status, 401);

        const db = require('../../server/config/db');
        const audit = await db.query(
            "SELECT method, success FROM audit_log WHERE action = 'password_reset' AND username = 'jsmith'"
        );
        assert.deepEqual(audit.rows, [{ method: 'security_questions', success: true }]);
    });

    test('wrong answer fails and increments failed attempts', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const wrong = answers.map((a, i) => (i === 2 ? { ...a, answer: 'nope' } : a));
        const res = await verifyWithQuestions('jsmith', wrong);
        assert.equal(res.status, 400);

        const db = require('../../server/config/db');
        const row = (await db.query("SELECT failed_attempts FROM users WHERE username = 'jsmith'")).rows[0];
        assert.equal(row.failed_attempts, 1);
    });

    test('repeating one known answer for the same question is rejected', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await api('POST', '/api/password/reset/verify-questions', {
            username: 'jsmith',
            answers: [answers[0], answers[0], answers[0]],
        });
        assert.equal(res.status, 400);
        assert.equal(res.body.data, undefined);
    });

    test('unenrolled and unknown users get the same generic error', async () => {
        await login(api, 'mjones', 'Welcome1!');
        const unenrolled = await api('POST', '/api/password/reset/verify-user', { username: 'mjones' });
        const unknown = await api('POST', '/api/password/reset/verify-user', { username: 'ghost' });
        assert.equal(unenrolled.status, 400);
        assert.equal(unknown.status, 400);
        assert.equal(unenrolled.body.message, unknown.body.message);
    });

    test('unknown users get stable decoy questions and the same failure as wrong answers', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');

        const a = await api('POST', '/api/password/reset/get-questions', { username: 'ghost' });
        const b = await api('POST', '/api/password/reset/get-questions', { username: 'ghost' });
        assert.equal(a.status, 200);
        assert.equal(a.body.data.length, 3);
        assert.deepEqual(a.body.data, b.body.data);

        const ghost = await api('POST', '/api/password/reset/verify-questions', {
            username: 'ghost',
            answers: a.body.data.map((q) => ({ questionId: q.id, answer: 'x' })),
        });
        const wrong = await verifyWithQuestions('jsmith', answers.map((x) => ({ ...x, answer: 'wrong' })));
        assert.equal(ghost.status, wrong.status);
        assert.equal(ghost.body.message, wrong.body.message);

        const ghostTotp = await api('POST', '/api/password/reset/verify-totp', { username: 'ghost', code: '123456' });
        const wrongTotp = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: '000000' });
        assert.equal(ghostTotp.body.message, wrongTotp.body.message);
    });

    test('answers and hashes are never returned by any endpoint', async () => {
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const admin = (await login(api, 'admin', 'Adm1nPass!')).token;
        const responses = [
            await api('POST', '/api/password/reset/get-questions', { username: 'jsmith' }),
            await api('GET', '/api/enrollment/security-questions', undefined, token),
            await api('GET', '/api/auth/me', undefined, token),
            await api('GET', '/api/admin/users', undefined, admin),
        ];
        for (const r of responses) {
            const text = JSON.stringify(r.body).toLowerCase();
            assert.ok(!text.includes('$2'), 'bcrypt hash leaked');
            assert.ok(!text.includes('springfield') && !/\brex\b/.test(text), 'answer leaked');
            assert.ok(!text.includes('totp_secret') && !text.includes('answer_hash'), 'secret field leaked');
        }
    });
});

describe('password reset via TOTP', () => {
    test('full flow with authenticator code', async () => {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');

        const verified = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30) });
        assert.equal(verified.status, 200);

        const set = await api('POST', '/api/password/reset/set-password', {
            resetToken: verified.body.data.resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        });
        assert.equal(set.status, 200, set.body.message);
        await login(api, 'jsmith', NEW_PASSWORD);
    });

    test('a code cannot be replayed, including the one used during enrollment', async () => {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const enrollmentCode = totpCode(secret);
        const replayEnroll = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: enrollmentCode });
        assert.equal(replayEnroll.status, 400);

        const code = totpCode(secret, 30);
        const results = await Promise.all([1, 2, 3].map(() =>
            api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code })));
        assert.equal(results.filter((r) => r.status === 200).length, 1);

        // An older step is rejected once a newer one has been used
        const older = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, -30) });
        assert.equal(older.status, 400);
    });

    test('rejects invalid and expired codes', async () => {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        for (const code of ['000000', totpCode(secret, -120), 'abcdef']) {
            const res = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code });
            assert.equal(res.status, 400, `accepted ${code}`);
        }
    });
});

describe('reset token handling', () => {
    async function getResetToken() {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30) });
        return res.body.data.resetToken;
    }

    test('token is single-use', async () => {
        const resetToken = await getResetToken();
        const body = { resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD };
        assert.equal((await api('POST', '/api/password/reset/set-password', body)).status, 200);

        const replay = await api('POST', '/api/password/reset/set-password', {
            ...body, newPassword: 'Another-Pass-9', confirmPassword: 'Another-Pass-9',
        });
        assert.equal(replay.status, 400);
        assert.match(replay.body.message, /already been used/);
    });

    test('concurrent submissions with the same token succeed at most once', async () => {
        const resetToken = await getResetToken();
        const attempts = ['Race-Pass-1a', 'Race-Pass-2b', 'Race-Pass-3c', 'Race-Pass-4d'].map((pw) =>
            api('POST', '/api/password/reset/set-password', { resetToken, newPassword: pw, confirmPassword: pw }));
        const results = await Promise.all(attempts);
        assert.equal(results.filter((r) => r.status === 200).length, 1);
    });

    test('policy failure releases the token so the user can retry', async () => {
        const resetToken = await getResetToken();
        const weak = await api('POST', '/api/password/reset/set-password', {
            resetToken, newPassword: 'Passw0rd!', confirmPassword: 'Passw0rd!',
        });
        assert.equal(weak.status, 400);
        assert.match(weak.body.message, /policy/);

        const retry = await api('POST', '/api/password/reset/set-password', {
            resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        });
        assert.equal(retry.status, 200);
    });

    test('rejects access tokens and forged tokens as reset tokens', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const jwt = require('jsonwebtoken');
        const forged = jwt.sign({ userId: 1, username: 'jsmith', type: 'password_reset', jti: 'x' }, 'wrong-secret');

        for (const resetToken of [token, forged, 'garbage']) {
            const res = await api('POST', '/api/password/reset/set-password', {
                resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
            });
            assert.equal(res.status, 400);
        }
    });
});

describe('account lockout', () => {
    const db = () => require('../../server/config/db');

    test('locked-out account is rejected even with a correct code', async () => {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        await db().query("UPDATE users SET failed_attempts = 5, last_failed_attempt = NOW() WHERE username = 'jsmith'");

        const res = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret) });
        assert.equal(res.status, 429);
        assert.equal(res.body.data, undefined);
    });

    test('5 wrong answers trigger lockout', async () => {
        const { answers } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const wrong = answers.map((a) => ({ ...a, answer: 'wrong' }));
        for (let i = 0; i < 5; i++) {
            assert.equal((await verifyWithQuestions('jsmith', wrong)).status, 400);
        }
        assert.equal((await verifyWithQuestions('jsmith', answers)).status, 429);
    });

    test('lockout expires after the lockout window and resets the counter', async () => {
        const { secret } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        await db().query(
            "UPDATE users SET failed_attempts = 5, last_failed_attempt = NOW() - INTERVAL '31 minutes' WHERE username = 'jsmith'"
        );

        const res = await api('POST', '/api/password/reset/verify-totp', { username: 'jsmith', code: totpCode(secret, 30) });
        assert.equal(res.status, 200);
        const row = (await db().query("SELECT failed_attempts FROM users WHERE username = 'jsmith'")).rows[0];
        assert.equal(row.failed_attempts, 0);
    });
});

describe('authenticated password change', () => {
    test('requires correct current password and applies new one', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        const wrong = await api('POST', '/api/password/change', {
            currentPassword: 'nope', newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        }, token);
        assert.equal(wrong.status, 401);

        const ok = await api('POST', '/api/password/change', {
            currentPassword: 'Passw0rd!', newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        }, token);
        assert.equal(ok.status, 200);
        await login(api, 'jsmith', NEW_PASSWORD);
    });
});
