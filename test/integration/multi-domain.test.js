// Second domain (AD2_*) receives the same password on change and reset. Must be set before setup loads config.
process.env.AD2_URL = 'ldaps://dc.second.example.test:636';
process.env.AD2_USER_SEARCH_BASE = 'OU=Users,DC=second,DC=example,DC=test';
process.env.AD2_DOMAIN_LABEL = 'Mail';
process.env.AD_DOMAIN_LABEL = 'Desktop';
process.env.SMTP_HOST = 'smtp.example.test';
process.env.MAIL_FROM = 'portal@example.test';
process.env.PORTAL_URL = 'https://portal.example.test';

const { startServer, resetState, login, enrollUser } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

let server;
let api;
let mockAd;
let db;
let sent = [];

before(async () => {
    server = await startServer();
    api = server.request;
    mockAd = require('../../server/services/mockLdapService');
    db = require('../../server/config/db');
    require('../../server/services/mailService').setTransport({ sendMail: async (m) => { sent.push(m); } });
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    sent = [];
});

const NEW_PASSWORD = 'Brand-New-Pass1';

async function changePassword(username, password, newPassword) {
    const { token } = await enrollUser(api, username, password);
    return api('POST', '/api/password/change', {
        currentPassword: password, newPassword, confirmPassword: newPassword,
    }, token);
}

async function resetToken(username, password) {
    const { answers } = await enrollUser(api, username, password);
    const questions = await api('POST', '/api/password/reset/get-questions', { username });
    const answerFor = new Map(answers.map((a) => [a.questionId, a.answer]));
    const verified = await api('POST', '/api/password/reset/verify-questions', {
        username,
        answers: questions.body.data.map((q) => ({ questionId: q.id, answer: answerFor.get(q.id) })),
    });
    assert.equal(verified.status, 200, verified.body.message);
    return verified.body.data.resetToken;
}

async function syncAudit(username) {
    return (await db.query(
        "SELECT success, details FROM audit_log WHERE action = 'password_sync' AND username = $1 ORDER BY id",
        [username]
    )).rows;
}

describe('password change', () => {
    test('updates both domains', async () => {
        const res = await changePassword('jsmith', 'Passw0rd!', NEW_PASSWORD);
        assert.equal(res.status, 200, res.body.message);
        assert.deepEqual(res.body.data.sync, { domain: 'Mail', status: 'synced' });

        await mockAd.authenticateUser('jsmith', NEW_PASSWORD);
        await mockAd.secondary.authenticateUser('jsmith', NEW_PASSWORD);
        assert.deepEqual(await syncAudit('jsmith'), [{ success: true, details: 'Mail: password updated' }]);
    });

    test('changes nothing when the second domain is unreachable', async () => {
        mockAd.secondary.setUnavailable(true);
        const res = await changePassword('jsmith', 'Passw0rd!', NEW_PASSWORD);
        assert.equal(res.status, 503);
        assert.match(res.body.message, /Mail is currently unavailable/);

        await mockAd.authenticateUser('jsmith', 'Passw0rd!');
    });

    test('reports a partial change when the second domain rejects the password', async () => {
        // Make the new password part of the Mail history only, so only Mail rejects it
        const mailUser = await mockAd.secondary.findUser('jsmith');
        await mockAd.secondary.changePassword(mailUser.dn, NEW_PASSWORD);
        await mockAd.secondary.changePassword(mailUser.dn, 'Other-Pass-22');

        const res = await changePassword('jsmith', 'Passw0rd!', NEW_PASSWORD);
        assert.equal(res.status, 200);
        assert.deepEqual(res.body.data.sync, { domain: 'Mail', status: 'failed' });
        assert.match(res.body.message, /changed in Desktop, but NOT in Mail because it does not meet the Mail password policy/);

        await mockAd.authenticateUser('jsmith', NEW_PASSWORD);
        await mockAd.secondary.authenticateUser('jsmith', 'Other-Pass-22');
        const [audit] = await syncAudit('jsmith');
        assert.equal(audit.success, false);
    });

    test('skips users that only exist in the first domain', async () => {
        const res = await changePassword('primary.only', 'Passw0rd!', NEW_PASSWORD);
        assert.equal(res.status, 200, res.body.message);
        assert.deepEqual(res.body.data.sync, { domain: 'Mail', status: 'not_found' });
        assert.match((await syncAudit('primary.only'))[0].details, /no account with this username/);
    });

    // Matching is by name only: these second-domain accounts must never receive a first-domain password
    async function assertRefused(username, password, pattern) {
        const res = await changePassword(username, password, NEW_PASSWORD);
        assert.equal(res.status, 200, res.body.message);
        assert.deepEqual(res.body.data.sync, { domain: 'Mail', status: 'not_found' });
        assert.match((await syncAudit(username))[0].details, pattern);

        mockAd.secondary.setAttributes(username, { userAccountControl: '512' }); // to check the password
        await mockAd.authenticateUser(username, NEW_PASSWORD);
        await mockAd.secondary.authenticateUser(username, password);
    }

    test('skips protected accounts (adminCount=1) in the second domain', async () => {
        await assertRefused('admin', 'Adm1nPass!', /protected account/);
    });

    test('skips accounts that are disabled in the second domain', async () => {
        mockAd.secondary.setAttributes('mjones', { userAccountControl: '514' });
        await assertRefused('mjones', 'Welcome1!', /disabled/);
    });

    test('skips the second-domain service account', async () => {
        const config = require('../../server/config/default');
        const original = config.ad.secondary.bindDN;
        config.ad.secondary.bindDN = String.raw`MAIL\mjones`;
        try {
            await assertRefused('mjones', 'Welcome1!', /service account/);
        } finally {
            config.ad.secondary.bindDN = original;
        }
    });
});

describe('password reset', () => {
    test('updates both domains', async () => {
        const token = await resetToken('jsmith', 'Passw0rd!');
        const res = await api('POST', '/api/password/reset/set-password', {
            resetToken: token, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        });
        assert.equal(res.status, 200, res.body.message);
        assert.deepEqual(res.body.data.sync, { domain: 'Mail', status: 'synced' });
        await mockAd.authenticateUser('jsmith', NEW_PASSWORD);
        await mockAd.secondary.authenticateUser('jsmith', NEW_PASSWORD);
    });

    test('keeps the reset token usable when the second domain is unreachable', async () => {
        const token = await resetToken('jsmith', 'Passw0rd!');
        const body = { resetToken: token, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD };

        mockAd.secondary.setUnavailable(true);
        const down = await api('POST', '/api/password/reset/set-password', body);
        assert.equal(down.status, 503);
        await mockAd.authenticateUser('jsmith', 'Passw0rd!');

        mockAd.secondary.setUnavailable(false);
        const retry = await api('POST', '/api/password/reset/set-password', body);
        assert.equal(retry.status, 200, retry.body.message);
        await mockAd.secondary.authenticateUser('jsmith', NEW_PASSWORD);
    });
});

describe('expiry reminders from the second domain (PASSWORD_REMINDER_SOURCE=secondary)', () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    let config;
    let reminders;
    const reminderMails = () => sent.filter((m) => /expires/.test(m.subject));

    before(() => {
        config = require('../../server/config/default');
        reminders = require('../../server/services/passwordReminderService');
    });
    beforeEach(() => { config.reminders.source = 'secondary'; });
    after(() => { config.reminders.source = 'primary'; });

    function mailExpiresIn(username, days) {
        mockAd.secondary.setAttributes(username, { passwordExpiresAt: new Date(Date.now() + days * DAY_MS - 60 * 1000) });
    }

    test('uses the second-domain expiry and mails the first-domain address', async () => {
        mailExpiresIn('mjones', 5);
        mockAd.setAttributes('mjones', { mail: 'mary@desktop.example.test' });

        assert.equal((await reminders.runOnce()).sent, 1);
        const [mail] = reminderMails();
        assert.equal(mail.to, 'mary@desktop.example.test');
        assert.equal(mail.subject, 'Your Mail password expires in 5 days');
        assert.match(mail.text, /https:\/\/portal\.example\.test/);
        assert.match(mail.text, /updates both your Desktop and Mail passwords/);
        assert.doesNotMatch(mail.text, /Ctrl\+Alt\+Del/, 'only the portal changes both domains');
    });

    test('a change in the portal resets the second-domain expiry', async () => {
        mailExpiresIn('jsmith', 2);
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        await api('POST', '/api/password/change', {
            currentPassword: 'Passw0rd!', newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        }, token);
        assert.equal((await reminders.runOnce()).due.length, 0);
    });

    test('skips accounts the portal cannot update or sign in', async () => {
        mailExpiresIn('admin', 3);                                   // protected in the second domain
        mailExpiresIn('mjones', 3);
        mockAd.setAttributes('mjones', { userAccountControl: '514' }); // disabled in the first domain
        mailExpiresIn('secondary.only', 3);                          // no first-domain account at all
        const result = await reminders.runOnce();
        assert.equal(result.due.length, 0);
        assert.equal(sent.length, 0);
        assert.equal(result.expiring, 3);
        assert.deepEqual(result.skipped, {
            'Mail: protected account (adminCount=1)': 1,
            'Desktop account disabled': 1,
            'no Desktop account': 1,
        });
    });

    test('primary source ignores the second-domain expiry', async () => {
        config.reminders.source = 'primary';
        mailExpiresIn('jsmith', 2);
        assert.equal((await reminders.runOnce()).due.length, 0);
    });
});
