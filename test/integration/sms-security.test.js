// SMS hardening: daily caps, the pinned directory number, first-use pinning and the cooldown race.
process.env.FACTOR_SMS = 'true';
process.env.SMS_API_URL = 'https://sms.example.test/send?to={mobile_plain}&text={message}';
process.env.SMS_COUNTRY_CODE = '+91';

const { startServer, resetState, login, DEFAULT_ANSWERS } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// jsmith's directory number in the mock is +919876500001
const USER = { username: 'jsmith', password: 'Passw0rd!' };

let server;
let api;
let db;
let mockAd;
let settingsService;
let sent;

before(async () => {
    server = await startServer();
    api = server.request;
    db = require('../../server/config/db');
    mockAd = require('../../server/services/mockLdapService');
    settingsService = require('../../server/services/settingsService');
    require('../../server/services/smsService').setSender(async (request) => {
        sent.push(request);
        return { response: 'queued' };
    });
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    await settingsService.refresh();
    sent = [];
});

function lastCode() {
    return sent.at(-1).text.match(/\b(\d{6})\b/)[1];
}

async function enrollWithSms() {
    const { token } = await login(api, USER.username, USER.password);
    const status = (await api('GET', '/api/enrollment/status', undefined, token)).body.data;
    const questions = (await api('GET', '/api/enrollment/questions', undefined, token)).body.data;
    const answers = questions.slice(0, status.questionCount).map((q, i) => ({ questionId: q.id, answer: DEFAULT_ANSWERS[i] }));
    assert.equal((await api('POST', '/api/enrollment/security-questions', { answers }, token)).status, 200);
    assert.equal((await api('POST', '/api/enrollment/sms/setup', {}, token)).status, 200);
    const verify = await api('POST', '/api/enrollment/sms/verify', { code: lastCode() }, token);
    assert.equal(verify.status, 200, verify.body.message);
    return token;
}

async function clearCooldown() {
    await db.query("UPDATE sms_codes SET created_at = created_at - INTERVAL '5 minutes'");
}

describe('SMS hardening', () => {
    test('the per-user daily cap stops further texts', async () => {
        const { token } = await login(api, 'admin', 'Adm1nPass!');
        assert.equal((await api('PUT', '/api/admin/settings', { settings: { 'sms.dailyLimitPerUser': '1' } }, token)).status, 200);
        await enrollWithSms();
        await clearCooldown();

        const res = await api('POST', '/api/password/reset/send-sms', { username: USER.username });
        assert.equal(res.status, 429);
        assert.equal(res.body.code, 'SMS_LIMIT');
        assert.equal(sent.length, 1, 'only the enrolment text went out');
        const audit = await db.query("SELECT details FROM audit_log WHERE action = 'sms_limit'");
        assert.deepEqual(audit.rows.map((r) => r.details), ['per-user limit']);
    });

    test('the portal-wide daily cap stops texts for everyone', async () => {
        await enrollWithSms();
        await clearCooldown();
        await db.query(`INSERT INTO audit_log (username, action, success)
                        SELECT 'someone', 'password_reset_sms', TRUE FROM generate_series(1, 500)`);

        const res = await api('POST', '/api/password/reset/send-sms', { username: USER.username });
        assert.equal(res.body.code, 'SMS_LIMIT');
        assert.deepEqual((await db.query("SELECT details FROM audit_log WHERE action = 'sms_limit'")).rows.map((r) => r.details),
            ['portal-wide limit']);
    });

    test('a directory number changed after verification gets no codes until the user confirms it', async () => {
        await enrollWithSms();
        await clearCooldown();
        mockAd.setAttributes(USER.username, { mobile: '+919876500099' });

        const res = await api('POST', '/api/password/reset/send-sms', { username: USER.username });
        assert.equal(res.status, 409);
        assert.equal(res.body.code, 'MOBILE_CHANGED');
        assert.equal(sent.length, 1);

        const { token } = await login(api, USER.username, USER.password);
        const status = (await api('GET', '/api/enrollment/status', undefined, token)).body.data;
        assert.equal(status.mobile.changedInDirectory, true);

        // Confirming: set SMS up again (password required, the account is enrolled) with the new number
        const setup = await api('POST', '/api/enrollment/sms/setup', { currentPassword: USER.password }, token);
        assert.equal(setup.status, 200, setup.body.message);
        assert.equal(sent.at(-1).to, '+919876500099');
        assert.equal((await api('POST', '/api/enrollment/sms/verify', { code: lastCode() }, token)).status, 200);

        await clearCooldown();
        const again = await api('POST', '/api/password/reset/send-sms', { username: USER.username });
        assert.equal(again.status, 200, again.body.message);
        assert.equal(sent.at(-1).to, '+919876500099');
    });

    test('an enrolment from before pinning is pinned by its first successful code', async () => {
        await enrollWithSms();
        await db.query('UPDATE users SET mobile_verified_hash = NULL');
        await clearCooldown();

        assert.equal((await api('POST', '/api/password/reset/send-sms', { username: USER.username })).status, 200);
        const verify = await api('POST', '/api/password/reset/verify-sms', { username: USER.username, code: lastCode() });
        assert.equal(verify.status, 200, verify.body.message);

        const row = (await db.query('SELECT mobile_verified_hash FROM users WHERE username = $1', [USER.username])).rows[0];
        assert.match(row.mobile_verified_hash, /^[0-9a-f]{64}$/);
    });

    test('two requests at the same moment send one text', async () => {
        await enrollWithSms();
        await clearCooldown();
        const before = sent.length;

        const results = await Promise.all([
            api('POST', '/api/password/reset/send-sms', { username: USER.username }),
            api('POST', '/api/password/reset/send-sms', { username: USER.username }),
        ]);
        assert.deepEqual(results.map((r) => r.status).sort(), [200, 429]);
        assert.equal(sent.length, before + 1);
    });
});
