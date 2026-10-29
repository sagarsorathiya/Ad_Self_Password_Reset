// SMS one-time codes: enrolment, the reset flow, and the gateway contract.
// The gateway settings must exist before setup loads config/default.js.
process.env.FACTOR_SMS = 'true';
process.env.SMS_API_URL = 'https://sms.example.test/send?to={mobile_plain}&text={message}';
process.env.SMS_COUNTRY_CODE = '+91';
process.env.PORTAL_NAME = 'Test Portal';

const { startServer, resetState, login, DEFAULT_ANSWERS } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// jsmith has a mobile number in the mock directory, mjones has none
const WITH_MOBILE = { username: 'jsmith', password: 'Passw0rd!' };
const NO_MOBILE = { username: 'mjones', password: 'Welcome1!' };
const NEW_PASSWORD = 'Brand-New-Pass1';

let server;
let api;
let db;
let smsService;
let smsOtpService;
let sent;
let failSending;

before(async () => {
    server = await startServer();
    api = server.request;
    db = require('../../server/config/db');
    smsService = require('../../server/services/smsService');
    smsOtpService = require('../../server/services/smsOtpService');
    // Stands in for the HTTP call, and records exactly what would have gone to the gateway
    smsService.setSender(async (request) => {
        if (failSending) throw new Error('Gateway refused the message');
        sent.push(request);
        return { response: 'queued' };
    });
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    sent = [];
    failSending = false;
});

// The 6-digit code out of the last message the gateway received
function lastCode() {
    return sent.at(-1).text.match(/\b(\d{6})\b/)[1];
}

async function saveQuestions(token) {
    const status = (await api('GET', '/api/enrollment/status', undefined, token)).body.data;
    const questions = (await api('GET', '/api/enrollment/questions', undefined, token)).body.data;
    const answers = questions.slice(0, status.questionCount)
        .map((q, i) => ({ questionId: q.id, answer: DEFAULT_ANSWERS[i] }));
    const res = await api('POST', '/api/enrollment/security-questions', { answers }, token);
    assert.equal(res.status, 200, res.body.message);
    return answers;
}

// Security questions plus SMS, which is all an enrolled account needs
async function enrollWithSms({ username, password }, mobile) {
    const { token } = await login(api, username, password);
    const answers = await saveQuestions(token);

    const setup = await api('POST', '/api/enrollment/sms/setup', mobile ? { mobile } : {}, token);
    assert.equal(setup.status, 200, setup.body.message);
    const verify = await api('POST', '/api/enrollment/sms/verify', { code: lastCode() }, token);
    assert.equal(verify.status, 200, verify.body.message);

    return { token, answers, masked: setup.body.data.mobileMasked };
}

// The cooldown is per user and purpose; tests that send twice clear it rather than waiting a minute
async function clearCooldown(username) {
    await db.query(
        `UPDATE sms_codes SET created_at = created_at - INTERVAL '5 minutes'
         WHERE user_id = (SELECT id FROM users WHERE username = $1)`,
        [username]
    );
}

describe('SMS one-time codes', () => {
    test('enrols with the mobile number held in the directory', async () => {
        const { token, masked } = await enrollWithSms(WITH_MOBILE);

        assert.equal(sent.length, 1);
        assert.equal(sent[0].to, '+919876500001');
        assert.match(sent[0].text, /Test Portal verification code is \d{6}/);
        // Never the whole number, and never the code
        assert.match(masked, /^\+91 •+ 01$/);

        const status = (await api('GET', '/api/enrollment/status', undefined, token)).body.data;
        assert.equal(status.smsEnabled, true);
        assert.equal(status.isEnrolled, true, 'questions plus one second factor is a complete enrolment');
        assert.equal(status.totpEnabled, false);
        assert.equal(status.mobile.source, 'ad');
    });

    test('asks for a number when the directory has none, and stores it only after verification', async () => {
        const { token } = await login(api, NO_MOBILE.username, NO_MOBILE.password);
        await saveQuestions(token);

        const missing = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(missing.status, 400);
        assert.equal(missing.body.code, 'MOBILE_REQUIRED');
        assert.equal(sent.length, 0);

        const bad = await api('POST', '/api/enrollment/sms/setup', { mobile: 'not a number' }, token);
        assert.equal(bad.body.code, 'MOBILE_INVALID');

        // A national number is completed with the configured dialling code
        const setup = await api('POST', '/api/enrollment/sms/setup', { mobile: '098765 43210' }, token);
        assert.equal(setup.status, 200, setup.body.message);
        assert.equal(sent.at(-1).to, '+919876543210');

        const before = await db.query('SELECT sms_enabled, mobile_number, mobile_pending FROM users WHERE username = $1', [NO_MOBILE.username]);
        assert.equal(before.rows[0].sms_enabled, false);
        assert.equal(before.rows[0].mobile_number, null, 'the number is only staged until a code proves the phone');
        assert.ok(before.rows[0].mobile_pending);

        const verify = await api('POST', '/api/enrollment/sms/verify', { code: lastCode() }, token);
        assert.equal(verify.status, 200, verify.body.message);

        const after = await db.query('SELECT sms_enabled, mobile_number, mobile_source FROM users WHERE username = $1', [NO_MOBILE.username]);
        assert.equal(after.rows[0].sms_enabled, true);
        assert.equal(after.rows[0].mobile_source, 'portal');
        // Stored encrypted, like a TOTP secret
        assert.ok(!after.rows[0].mobile_number.includes('9876543210'));
    });

    test('accepts the number however the user writes it, without doubling the dialling code', async () => {
        const mobileService = require('../../server/services/mobileService');
        // All of these are the same Indian mobile; 919876543210 already carries the code (production
        // 2026-10-28: an admin typed it that way and the portal sent +91919876543210 to the gateway)
        for (const written of ['9876543210', '09876543210', '+91 98765 43210', '0091-9876543210', '919876543210', '(+91) 98765-43210']) {
            assert.equal(mobileService.normalize(written), '+919876543210', `from "${written}"`);
        }
        // A 10-digit national number that happens to start with 91 is still prefixed
        assert.equal(mobileService.normalize('9187654321'), '+919187654321');
        assert.equal(mobileService.normalize('not a number'), null);
    });

    test('rejects a wrong code, and kills the code after five attempts', async () => {
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);
        await api('POST', '/api/enrollment/sms/setup', {}, token);
        const code = lastCode();

        const wrong = await api('POST', '/api/enrollment/sms/verify', { code: '000000' }, token);
        assert.equal(wrong.status, 400);
        assert.match(wrong.body.message, /Incorrect code/);

        for (let i = 0; i < 4; i++) {
            await api('POST', '/api/enrollment/sms/verify', { code: '000000' }, token);
        }
        const dead = await api('POST', '/api/enrollment/sms/verify', { code }, token);
        assert.equal(dead.status, 400);
        assert.match(dead.body.message, /request a new one/);
    });

    test('a code works only once', async () => {
        const { token } = await enrollWithSms(WITH_MOBILE);
        const code = lastCode();
        const replay = await api('POST', '/api/enrollment/sms/verify', { code }, token);
        assert.equal(replay.status, 400);
    });

    test('a second code cannot be requested straight away', async () => {
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);
        await api('POST', '/api/enrollment/sms/setup', {}, token);

        const again = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(again.status, 429);
        assert.equal(again.body.code, 'SMS_COOLDOWN');
        assert.ok(again.body.data.resendAfter > 0);
        assert.equal(sent.length, 1);

        // A new code replaces the old one once the wait is over
        await clearCooldown(WITH_MOBILE.username);
        const first = lastCode();
        const resend = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(resend.status, 200);
        const stale = await api('POST', '/api/enrollment/sms/verify', { code: first }, token);
        assert.equal(stale.status, 400, 'the earlier code stops working');
        const fresh = await api('POST', '/api/enrollment/sms/verify', { code: lastCode() }, token);
        assert.equal(fresh.status, 200, fresh.body.message);
    });

    test('a gateway failure leaves no code behind, so the user can try again', async () => {
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);

        failSending = true;
        const res = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(res.status, 502);

        const rows = await db.query('SELECT COUNT(*)::int AS n FROM sms_codes');
        assert.equal(rows.rows[0].n, 0);

        failSending = false;
        const retry = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(retry.status, 200, 'the failed attempt does not sit in the cooldown');
    });

    test('resets a password with a code sent by SMS', async () => {
        await enrollWithSms(WITH_MOBILE);
        sent = [];

        const user = await api('POST', '/api/password/reset/verify-user', { username: WITH_MOBILE.username });
        assert.equal(user.status, 200, user.body.message);
        assert.ok(user.body.data.availableMethods.includes('sms'));
        assert.ok(!user.body.data.availableMethods.includes('totp'), 'this user never set up an authenticator');
        assert.match(user.body.data.mobileMasked, /01$/);

        const send = await api('POST', '/api/password/reset/send-sms', { username: WITH_MOBILE.username });
        assert.equal(send.status, 200, send.body.message);
        assert.equal(sent.length, 1);

        const wrong = await api('POST', '/api/password/reset/verify-sms', { username: WITH_MOBILE.username, code: '000000' });
        assert.equal(wrong.status, 400);

        const verify = await api('POST', '/api/password/reset/verify-sms', {
            username: WITH_MOBILE.username,
            code: lastCode(),
        });
        assert.equal(verify.status, 200, verify.body.message);

        const done = await api('POST', '/api/password/reset/set-password', {
            resetToken: verify.body.data.resetToken,
            newPassword: NEW_PASSWORD,
            confirmPassword: NEW_PASSWORD,
        });
        assert.equal(done.status, 200, done.body.message);

        const audit = await db.query(
            "SELECT method FROM audit_log WHERE action = 'password_reset' AND username = $1 AND success = TRUE",
            [WITH_MOBILE.username]
        );
        assert.equal(audit.rows[0].method, 'sms');

        const after = await login(api, WITH_MOBILE.username, NEW_PASSWORD);
        assert.ok(after.token);
    });

    test('an unknown account looks exactly like a real one and gets no message', async () => {
        const res = await api('POST', '/api/password/reset/send-sms', { username: 'nobody.here' });
        assert.equal(res.status, 200);
        assert.match(res.body.data.mobileMasked, /^\+91 •+ \d{2}$/);
        assert.equal(sent.length, 0, 'nothing is sent for an account that does not exist');

        const verify = await api('POST', '/api/password/reset/verify-sms', { username: 'nobody.here', code: '123456' });
        assert.equal(verify.status, 400);
        assert.match(verify.body.message, /Incorrect code/);
    });

    test('switching the factor off hides it from enrolment and from the reset flow', async () => {
        await enrollWithSms(WITH_MOBILE);
        const { token: adminToken } = await login(api, 'admin', 'Adm1nPass!');

        const off = await api('PUT', '/api/admin/settings', {
            settings: { 'factors.sms': 'false', 'factors.totp': 'true' },
        }, adminToken);
        assert.equal(off.status, 200, off.body.message);

        // Under the 'either' policy the security questions remain, but the code is no longer offered
        const user = await api('POST', '/api/password/reset/verify-user', { username: WITH_MOBILE.username });
        assert.equal(user.status, 200, user.body.message);
        assert.deepEqual(user.body.data.availableMethods, ['security_questions']);
        assert.equal(user.body.data.mobileMasked, null);

        const send = await api('POST', '/api/password/reset/send-sms', { username: WITH_MOBILE.username });
        assert.equal(send.status, 400);
        assert.equal(sent.length, 1, 'only the enrolment message was ever sent');

        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        const setup = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(setup.body.code, 'FACTOR_DISABLED');

        // Restored for the tests that follow in this file
        await api('PUT', '/api/admin/settings', { settings: { 'factors.sms': 'true' } }, adminToken);
    });

    test('at least one second factor must stay enabled, and SMS needs a gateway', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');

        const none = await api('PUT', '/api/admin/settings', {
            settings: { 'factors.totp': 'false', 'factors.sms': 'false' },
        }, token);
        assert.equal(none.status, 400);
        assert.match(none.body.message, /at least one second factor/i);

        const noGateway = await api('PUT', '/api/admin/settings', {
            settings: { 'factors.sms': 'true', 'sms.url': '' },
        }, token);
        assert.equal(noGateway.status, 400);
        assert.match(noGateway.body.message, /gateway URL/i);
    });

    test('the gateway request fills in the template and escapes what it substitutes', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        const saved = await api('PUT', '/api/admin/settings', {
            settings: {
                'sms.url': 'https://gw.example.test/send',
                'sms.method': 'POST',
                'sms.bodyType': 'json',
                'sms.bodyTemplate': '{"to": "{mobile}", "body": "{message}", "from": "{sender}"}',
                'sms.senderId': 'PORTAL',
                'sms.headers': 'Authorization: Bearer secret-key',
                'sms.messageTemplate': 'Code {otp}. Valid {minutes} min. "Quoted" \\ backslash.',
            },
        }, token);
        assert.equal(saved.status, 200, saved.body.message);
        // The API key is never handed back to the browser
        assert.equal(saved.body.data.sms.headers, '********');

        await enrollWithSms(WITH_MOBILE);

        const request = sent.at(-1);
        assert.equal(request.method, 'POST');
        assert.equal(request.headers.Authorization, 'Bearer secret-key');
        assert.equal(request.headers['Content-Type'], 'application/json');
        // The quotes and the backslash in the message must not break the JSON body
        const body = JSON.parse(request.body);
        assert.equal(body.to, '+919876500001');
        assert.equal(body.from, 'PORTAL');
        assert.match(body.body, /^Code \d{6}\. Valid 10 min\. "Quoted" \\ backslash\.$/);
    });

    test('a GET gateway URL percent-encodes the number and the message', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        await api('PUT', '/api/admin/settings', {
            settings: {
                'sms.url': 'https://gw.example.test/send?to={mobile}&text={message}',
                'sms.method': 'GET',
                'sms.messageTemplate': 'Code {otp} & nothing else',
            },
        }, token);

        await enrollWithSms(WITH_MOBILE);

        const url = new URL(sent.at(-1).url);
        assert.equal(url.searchParams.get('to'), '+919876500001');
        assert.match(url.searchParams.get('text'), /^Code \d{6} & nothing else$/);
        // The raw query string is encoded, so the & inside the message cannot add a parameter
        assert.match(sent.at(-1).url, /text=Code%20\d{6}%20%26%20nothing%20else/);
    });

    test('an administrator can send a test message', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');

        const bad = await api('POST', '/api/admin/settings/test-sms', { to: 'abc' }, token);
        assert.equal(bad.status, 400);

        await api('PUT', '/api/admin/settings', {
            settings: { 'sms.messageTemplate': '{otp}-is-OTP-For-Access-OF-VPN' },
        }, token);

        const ok = await api('POST', '/api/admin/settings/test-sms', { to: '+919876500002' }, token);
        assert.equal(ok.status, 200, ok.body.message);
        assert.equal(sent.at(-1).to, '+919876500002');
        assert.equal(ok.body.data.gatewayResponse, 'queued');
        // The test must use the configured template, not wording of its own: where the operator only
        // delivers registered templates, anything else is dropped while the gateway still reports success
        assert.match(sent.at(-1).text, /^\d{6}-is-OTP-For-Access-OF-VPN$/);

        failSending = true;
        const failed = await api('POST', '/api/admin/settings/test-sms', { to: '+919876500002' }, token);
        assert.equal(failed.status, 502);

        const audit = await db.query("SELECT success FROM audit_log WHERE action = 'sms_test' ORDER BY id");
        assert.deepEqual(audit.rows.map((r) => r.success), [true, false]);
    });

    test('resetting an enrolment clears the number and any outstanding code', async () => {
        await enrollWithSms(WITH_MOBILE);
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        const id = (await db.query('SELECT id FROM users WHERE username = $1', [WITH_MOBILE.username])).rows[0].id;

        const res = await api('PUT', `/api/admin/users/${id}/reset-enrollment`, {}, token);
        assert.equal(res.status, 200, res.body.message);

        const user = (await db.query('SELECT sms_enabled, mobile_number, mobile_source, is_enrolled FROM users WHERE id = $1', [id])).rows[0];
        assert.equal(user.sms_enabled, false);
        assert.equal(user.mobile_number, null);
        assert.equal(user.mobile_source, null);
        assert.equal(user.is_enrolled, false);

        const codes = await db.query('SELECT COUNT(*)::int AS n FROM sms_codes WHERE user_id = $1', [id]);
        assert.equal(codes.rows[0].n, 0);
    });

    test("the 'both' policy will not text a code before the questions are answered", async () => {
        const config = require('../../server/config/default');
        const { answers } = await enrollWithSms(WITH_MOBILE);
        sent = [];
        config.reset.policy = 'both';
        try {
            const early = await api('POST', '/api/password/reset/send-sms', { username: WITH_MOBILE.username });
            assert.equal(early.status, 400);
            assert.equal(early.body.code, 'STEP_REQUIRED');
            assert.equal(sent.length, 0, 'no message goes out before the first factor');

            const questions = await api('POST', '/api/password/reset/verify-questions', {
                username: WITH_MOBILE.username,
                answers,
            });
            assert.equal(questions.status, 200, questions.body.message);
            assert.deepEqual(questions.body.data.nextSteps, ['sms']);
            const { stepToken } = questions.body.data;

            const send = await api('POST', '/api/password/reset/send-sms', { username: WITH_MOBILE.username, stepToken });
            assert.equal(send.status, 200, send.body.message);

            const verify = await api('POST', '/api/password/reset/verify-sms', {
                username: WITH_MOBILE.username,
                code: lastCode(),
                stepToken,
            });
            assert.equal(verify.status, 200, verify.body.message);
            const decoded = JSON.parse(Buffer.from(verify.body.data.resetToken.split('.')[1], 'base64url'));
            assert.equal(decoded.method, 'security_questions+sms');
        } finally {
            config.reset.policy = 'either';
        }
    });

    test('a code expires', async () => {
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);
        await api('POST', '/api/enrollment/sms/setup', {}, token);
        const code = lastCode();

        await db.query(
            `UPDATE sms_codes SET expires_at = NOW() - INTERVAL '1 minute'
             WHERE user_id = (SELECT id FROM users WHERE username = $1)`,
            [WITH_MOBILE.username]
        );

        const res = await api('POST', '/api/enrollment/sms/verify', { code }, token);
        assert.equal(res.status, 400);
        assert.match(res.body.message, /expired/);
        assert.equal(smsOtpService.CODE_TTL_MINUTES, 10);
    });
});
