// SMS gateway outages: one safe retry, and a "try again later" answer instead of a generic failure.
// The gateway settings must exist before setup loads config/default.js.
process.env.FACTOR_SMS = 'true';
process.env.SMS_API_URL = 'https://sms.example.test/send?to={mobile_plain}&text={message}';
process.env.SMS_COUNTRY_CODE = '+91';

const http = require('http');
const { startServer, resetState, login, DEFAULT_ANSWERS } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const WITH_MOBILE = { username: 'jsmith', password: 'Passw0rd!' };

let server;
let api;
let db;
let smsService;
let settingsService;

// A local stand-in for the provider: answers each request with the next queued [status, body]
let gateway;
let gatewayUrl;
let replies = [];
let hits = 0;

before(async () => {
    server = await startServer();
    api = server.request;
    db = require('../../server/config/db');
    smsService = require('../../server/services/smsService');
    settingsService = require('../../server/services/settingsService');
    smsService.setRetryDelay(0);

    gateway = http.createServer((req, res) => {
        hits += 1;
        const [status, body] = replies.shift() || [200, 'queued'];
        res.writeHead(status, { 'Content-Type': 'text/plain' });
        res.end(body);
    });
    await new Promise((resolve) => gateway.listen(0, '127.0.0.1', resolve));
    gatewayUrl = `http://127.0.0.1:${gateway.address().port}/send?to={mobile_plain}&text={message}`;
});
after(() => {
    smsService.setSender(null);
    gateway?.close();
    server?.close();
});
beforeEach(async () => {
    await resetState();
    replies = [];
    hits = 0;
    smsService.setSender(null);
    settingsService.current().sms.url = gatewayUrl;
    settingsService.current().sms.successText = '';
});

async function saveQuestions(token) {
    const status = (await api('GET', '/api/enrollment/status', undefined, token)).body.data;
    const questions = (await api('GET', '/api/enrollment/questions', undefined, token)).body.data;
    const answers = questions.slice(0, status.questionCount)
        .map((q, i) => ({ questionId: q.id, answer: DEFAULT_ANSWERS[i] }));
    const res = await api('POST', '/api/enrollment/security-questions', { answers }, token);
    assert.equal(res.status, 200, res.body.message);
}

async function lastAudit(action) {
    return (await db.query(
        'SELECT success, details FROM audit_log WHERE action = $1 ORDER BY id DESC LIMIT 1', [action]
    )).rows[0];
}

describe('smsService against a real HTTP gateway', () => {
    const message = { to: '+919876500001', text: 'test' };

    test('a 503 is retried once and the second answer counts', async () => {
        replies = [[503, 'No server is available'], [200, 'queued']];
        const result = await smsService.send(message);
        assert.equal(hits, 2);
        assert.equal(result.response, 'queued');
        assert.equal(result.retriedAfter, 'HTTP 503');
    });

    test('two 503s fail as temporary and say a retry happened', async () => {
        replies = [[503, 'down'], [503, 'still down']];
        await assert.rejects(smsService.send(message), (err) => {
            assert.equal(smsService.isTemporaryFailure(err), true);
            assert.match(err.message, /HTTP 503/);
            assert.match(err.message, /retried once after: HTTP 503/);
            return true;
        });
        assert.equal(hits, 2);
    });

    test('a 500 or 504 is temporary but never retried (the text may have gone out)', async () => {
        for (const status of [500, 504]) {
            hits = 0;
            replies = [[status, 'error']];
            await assert.rejects(smsService.send(message), (err) => smsService.isTemporaryFailure(err));
            assert.equal(hits, 1, `HTTP ${status} is sent once`);
        }
    });

    test('a 4xx answer is neither temporary nor retried', async () => {
        replies = [[400, 'invalid number']];
        await assert.rejects(smsService.send(message), (err) => !smsService.isTemporaryFailure(err));
        assert.equal(hits, 1);
    });

    test('a 200 without the success marker is not retried (the provider may have sent it)', async () => {
        settingsService.current().sms.successText = 'uniqueid';
        replies = [[200, '{"status":"error"}']];
        await assert.rejects(smsService.send(message), (err) => !smsService.isTemporaryFailure(err));
        assert.equal(hits, 1);
    });

    test('a connection that never opens is retried once', async () => {
        // Port 1 on loopback refuses the connection at once
        settingsService.current().sms.url = 'http://127.0.0.1:1/send?to={mobile_plain}';
        await assert.rejects(smsService.send(message), (err) => {
            assert.equal(smsService.isTemporaryFailure(err), true);
            assert.match(err.message, /retried once after: no connection/);
            return true;
        });
    });
});

describe('what users see when the provider is down', () => {
    test('enrolment answers 503 SMS_UNAVAILABLE and suggests the authenticator app', async () => {
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);
        replies = [[503, 'down'], [503, 'down']];

        const res = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(res.status, 503);
        assert.equal(res.body.code, 'SMS_UNAVAILABLE');
        assert.match(res.body.message, /not responding right now/);
        assert.match(res.body.message, /authenticator app/);

        const row = await lastAudit('enrollment_sms');
        assert.equal(row.success, false);
        assert.match(row.details, /retried once after: HTTP 503/);

        const codes = await db.query('SELECT COUNT(*)::int AS n FROM sms_codes');
        assert.equal(codes.rows[0].n, 0, 'no code is left behind to block the next try');
    });

    test('a send that worked on the second attempt is audited as such', async () => {
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);
        replies = [[503, 'down'], [200, 'queued']];

        const res = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(res.status, 200, res.body.message);
        const row = await lastAudit('enrollment_sms');
        assert.equal(row.success, true);
        assert.match(row.details, /second attempt; first failed: HTTP 503/);
    });

    test('a permanent refusal keeps the general 502 message', async () => {
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);
        replies = [[400, 'invalid number']];

        const res = await api('POST', '/api/enrollment/sms/setup', {}, token);
        assert.equal(res.status, 502);
        assert.equal(res.body.code, undefined);
        assert.equal(hits, 1);
    });

    test('reset send-sms answers 503 SMS_UNAVAILABLE and audits the failure', async () => {
        // Enrol with SMS first (questions + a code that arrives)
        const { token } = await login(api, WITH_MOBILE.username, WITH_MOBILE.password);
        await saveQuestions(token);
        let code = null;
        smsService.setSender(async (request) => {
            code = request.text.match(/\b(\d{6})\b/)[1];
            return { response: 'queued' };
        });
        assert.equal((await api('POST', '/api/enrollment/sms/setup', {}, token)).status, 200);
        assert.equal((await api('POST', '/api/enrollment/sms/verify', { code }, token)).status, 200);

        // Then the provider goes down
        smsService.setSender(null);
        replies = [[503, 'down'], [503, 'down']];
        const res = await api('POST', '/api/password/reset/send-sms', { username: WITH_MOBILE.username });
        assert.equal(res.status, 503);
        assert.equal(res.body.code, 'SMS_UNAVAILABLE');
        assert.match(res.body.message, /try again in a few minutes/);

        const row = await lastAudit('password_reset_sms');
        assert.equal(row.success, false);
        assert.match(row.details, /^Code not sent: SMS gateway returned HTTP 503/);
    });
});
