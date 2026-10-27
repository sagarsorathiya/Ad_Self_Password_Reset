// Admin-managed mail and reminder settings (Administration -> Mail & Reminders): validation, the stored
// override layered over .env, the masked SMTP password, the test mail and the manual reminder run.
process.env.SMTP_HOST = 'smtp.example.test';
process.env.MAIL_FROM = 'Password Portal <portal@example.test>';
process.env.PASSWORD_REMINDER_DAYS = '14,7,3,1';
process.env.PASSWORD_REMINDER_HOUR = '9';

const { startServer, resetState, login } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const DAY_MS = 24 * 60 * 60 * 1000;

let server;
let api;
let db;
let mockAd;
let mailService;
let settingsService;
let sent;
let failSending;

before(async () => {
    server = await startServer();
    api = server.request;
    db = require('../../server/config/db');
    mockAd = require('../../server/services/mockLdapService');
    mailService = require('../../server/services/mailService');
    settingsService = require('../../server/services/settingsService');
    mailService.setTransport({
        sendMail: async (message) => {
            if (failSending) throw new Error('Relay refused the message');
            sent.push(message);
        },
    });
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    await settingsService.refresh();
    sent = [];
    failSending = false;
});

async function adminToken() {
    return (await login(api, 'admin', 'Adm1nPass!')).token;
}

describe('mail and reminder settings', () => {
    test('only admins can read or change them', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        assert.equal((await api('GET', '/api/admin/settings', undefined, token)).status, 403);
        assert.equal((await api('PUT', '/api/admin/settings', { settings: {} }, token)).status, 403);
        assert.equal((await api('GET', '/api/admin/settings')).status, 401);
    });

    test('reports the .env values until something is stored', async () => {
        const token = await adminToken();
        const { body } = await api('GET', '/api/admin/settings', undefined, token);
        assert.equal(body.data.mail.host, 'smtp.example.test');
        assert.deepEqual(body.data.reminders.days, [14, 7, 3, 1]);
        assert.deepEqual(body.data.overrides, []);
        assert.equal(body.data.envDefaults.hour, 9);
    });

    test('stores day stages, hour and on/off, and applies them without a restart', async () => {
        const token = await adminToken();
        const res = await api('PUT', '/api/admin/settings', {
            settings: { 'reminders.days': '7, 6,5,4,3,2,1, 14', 'reminders.hour': '7', 'reminders.enabled': 'true' },
        }, token);

        assert.equal(res.status, 200);
        // Sorted descending and de-duplicated
        assert.deepEqual(res.body.data.reminders.days, [14, 7, 6, 5, 4, 3, 2, 1]);
        assert.equal(res.body.data.reminders.hour, 7);
        assert.equal(settingsService.current().reminders.days.join(','), '14,7,6,5,4,3,2,1');
        assert.ok(res.body.data.overrides.includes('reminders.days'));

        const audit = (await db.query("SELECT details FROM audit_log WHERE action = 'settings_updated'")).rows;
        assert.equal(audit.length, 1);
        assert.ok(audit[0].details.includes('reminders.days'));
    });

    test('rejects invalid values and keeps the previous ones', async () => {
        const token = await adminToken();
        const cases = [
            { 'reminders.days': 'soon' },
            { 'reminders.days': '' },
            { 'reminders.hour': '24' },
            { 'mail.port': '70000' },
            { 'reminders.source': 'tertiary' },
            // No second domain is configured in this test run
            { 'reminders.source': 'secondary' },
            { 'unknown.key': 'x' },
        ];
        for (const settings of cases) {
            const res = await api('PUT', '/api/admin/settings', { settings }, token);
            assert.equal(res.status, 400, JSON.stringify(settings));
            assert.equal(res.body.success, false);
        }
        assert.deepEqual(settingsService.current().reminders.days, [14, 7, 3, 1]);
        assert.equal((await api('PUT', '/api/admin/settings', { settings: 'nope' }, token)).status, 400);
    });

    test('refuses reminders without an SMTP host and a host without a From address', async () => {
        const token = await adminToken();
        let res = await api('PUT', '/api/admin/settings', {
            settings: { 'mail.host': '', 'reminders.enabled': 'true' },
        }, token);
        assert.equal(res.status, 400);
        assert.match(res.body.message, /SMTP host/i);

        res = await api('PUT', '/api/admin/settings', {
            settings: { 'mail.host': 'relay.example.test', 'mail.from': '' },
        }, token);
        assert.equal(res.status, 400);
        assert.match(res.body.message, /From address/i);
    });

    test('an empty SMTP host turns mail off instead of falling back to .env', async () => {
        const token = await adminToken();
        const res = await api('PUT', '/api/admin/settings', {
            settings: { 'mail.host': '', 'reminders.enabled': 'false' },
        }, token);
        assert.equal(res.status, 200);
        assert.equal(settingsService.current().mail.host, '');
        assert.equal(mailService.isEnabled(), false);
        // Still reported, so the panel can show what .env would give
        assert.equal(res.body.data.envDefaults.host, 'smtp.example.test');

        assert.equal((await api('POST', '/api/admin/settings/test-mail', { to: 'a@example.test' }, token)).status, 400);
        assert.equal((await api('POST', '/api/admin/reminders/run', { send: true }, token)).status, 400);
    });

    test('never returns the SMTP password and keeps it when the placeholder is sent back', async () => {
        const token = await adminToken();
        await api('PUT', '/api/admin/settings', {
            settings: { 'mail.user': 'portal@example.test', 'mail.password': 'relay-secret' },
        }, token);

        const { body } = await api('GET', '/api/admin/settings', undefined, token);
        assert.equal(body.data.mail.password, settingsService.SECRET_PLACEHOLDER);
        assert.equal(JSON.stringify(body).includes('relay-secret'), false);
        // Stored encrypted, not in clear text
        const stored = (await db.query("SELECT value FROM app_settings WHERE key = 'mail.password'")).rows[0].value;
        assert.notEqual(stored, 'relay-secret');
        assert.equal(settingsService.current().mail.password, 'relay-secret');

        await api('PUT', '/api/admin/settings', {
            settings: { 'mail.password': settingsService.SECRET_PLACEHOLDER, 'mail.user': 'portal@example.test' },
        }, token);
        assert.equal(settingsService.current().mail.password, 'relay-secret');

        // An empty value removes the login again (the relay accepts the server by IP)
        await api('PUT', '/api/admin/settings', { settings: { 'mail.password': '', 'mail.user': '' } }, token);
        assert.equal(settingsService.current().mail.password, '');
        assert.equal(settingsService.current().mail.user, '');
    });

    test('a stored SMTP host is used for the next mail', async () => {
        const token = await adminToken();
        await api('PUT', '/api/admin/settings', { settings: { 'mail.from': 'Changed <new@example.test>' } }, token);

        const res = await api('POST', '/api/admin/settings/test-mail', { to: 'someone@example.test' }, token);
        assert.equal(res.status, 200);
        assert.equal(sent.length, 1);
        assert.equal(sent[0].to, 'someone@example.test');
        assert.match(sent[0].text, /smtp\.example\.test:25/);

        const audit = (await db.query("SELECT success FROM audit_log WHERE action = 'mail_test'")).rows;
        assert.equal(audit[0].success, true);
    });

    test('the test mail validates the address and reports a relay failure', async () => {
        const token = await adminToken();
        assert.equal((await api('POST', '/api/admin/settings/test-mail', { to: 'not-an-address' }, token)).status, 400);

        failSending = true;
        const res = await api('POST', '/api/admin/settings/test-mail', { to: 'someone@example.test' }, token);
        assert.equal(res.status, 502);
        assert.match(res.body.message, /refused/i);
        const audit = (await db.query("SELECT success FROM audit_log WHERE action = 'mail_test'")).rows;
        assert.equal(audit.at(-1).success, false);
    });

    test('previews the reminder run without sending, then sends on demand', async () => {
        const token = await adminToken();
        mockAd.setAttributes('jsmith', { passwordExpiresAt: new Date(Date.now() + 5 * DAY_MS) });
        await api('PUT', '/api/admin/settings', { settings: { 'reminders.days': '14,7,6,5,4,3,2,1' } }, token);

        const preview = await api('POST', '/api/admin/reminders/run', {}, token);
        assert.equal(preview.status, 200);
        assert.equal(preview.body.data.send, false);
        assert.equal(sent.length, 0);
        // The overview covers every scanned account, not only the ones due now
        assert.ok(preview.body.data.withExpiry >= 1);
        assert.ok(preview.body.data.inWindow >= 1);
        assert.equal(preview.body.data.remindedTotal, 0);
        const due = preview.body.data.due.find((d) => d.username === 'jsmith');
        assert.equal(due.daysLeft, 5);
        assert.equal((await db.query('SELECT 1 FROM password_reminders')).rows.length, 0);

        const run = await api('POST', '/api/admin/reminders/run', { send: true }, token);
        assert.equal(run.status, 200);
        assert.equal(run.body.data.sent, preview.body.data.dueTotal);
        assert.ok(sent.some((m) => /expires in 5 days/i.test(m.subject)));

        // The same stage is not mailed twice, and those users are now reported as already reminded
        const again = await api('POST', '/api/admin/reminders/run', { send: true }, token);
        assert.equal(again.body.data.sent, 0);
        assert.equal(again.body.data.dueTotal, 0);
        assert.equal(again.body.data.remindedTotal, run.body.data.sent);
        const reminded = again.body.data.reminded.find((r) => r.username === 'jsmith');
        assert.equal(reminded.stage, 5);
        assert.ok(reminded.sentAt);

        const audit = (await db.query("SELECT details FROM audit_log WHERE action = 'reminder_run' ORDER BY id")).rows;
        assert.equal(audit.length, 3);
        assert.match(audit[0].details, /preview/);
    });
});
