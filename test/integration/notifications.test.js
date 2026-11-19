// Password-changed alerts and expiry reminders. Mail settings must be set before setup loads config.
process.env.SMTP_HOST = 'smtp.example.test';
process.env.MAIL_FROM = 'Password Portal <portal@example.test>';
process.env.PORTAL_URL = 'https://portal.example.test';
process.env.PORTAL_NAME = 'Test Portal';

const { startServer, resetState, login, enrollUser } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const DAY_MS = 24 * 60 * 60 * 1000;
const NEW_PASSWORD = 'Brand-New-Pass1';

let server;
let api;
let mockAd;
let db;
let mailService;
let reminders;
let sent;
let failSending;

before(async () => {
    server = await startServer();
    api = server.request;
    mockAd = require('../../server/services/mockLdapService');
    db = require('../../server/config/db');
    mailService = require('../../server/services/mailService');
    reminders = require('../../server/services/passwordReminderService');
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
    sent = [];
    failSending = false;
});

// The alert is sent after the response, so wait for its audit row
async function waitForNotification(username) {
    for (let i = 0; i < 50; i++) {
        const rows = (await db.query(
            "SELECT success, details FROM audit_log WHERE action = 'notification' AND username = $1",
            [username]
        )).rows;
        if (rows.length) return rows[0];
        await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error(`No notification audit row for ${username}`);
}

// The text part wraps at 76 characters; phrases are checked with the line breaks flattened
const flat = (text) => text.replace(/\s+/g, ' ');

// Enrolling sends its own security alert after the response: let it land, then count from zero
async function afterEnrolment(username) {
    for (let i = 0; i < 50; i++) {
        const rows = (await db.query(
            "SELECT 1 FROM audit_log WHERE action = 'notification' AND username = $1 AND details LIKE 'Security alert%'",
            [username]
        )).rows;
        if (rows.length) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
    }
    await db.query("DELETE FROM audit_log WHERE action = 'notification'");
    sent.length = 0;
}

async function changePassword(username, password) {
    const { token } = await enrollUser(api, username, password);
    await afterEnrolment(username);
    const res = await api('POST', '/api/password/change', {
        currentPassword: password, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
    }, token);
    assert.equal(res.status, 200, res.body.message);
}

describe('password-changed alert', () => {
    test('is mailed to the AD address after a change, with IP and browser', async () => {
        await changePassword('jsmith', 'Passw0rd!');
        const audit = await waitForNotification('jsmith');

        assert.equal(audit.success, true);
        assert.equal(sent.length, 1);
        assert.equal(sent[0].to, 'jsmith@example.local');
        assert.equal(sent[0].from, 'Password Portal <portal@example.test>');
        assert.equal(sent[0].subject, 'Your password was changed');
        assert.match(sent[0].text, /IP address:\s+\S*127\.0\.0\.1/);
        assert.match(sent[0].text, /Device:\s+\S+/);
        assert.match(sent[0].text, /How:\s+Signed in with the current password/);
        assert.match(flat(sent[0].text), /If you did not make this change, contact IT immediately/);
        assert.match(sent[0].text, /Open the password portal: https:\/\/portal\.example\.test/);
        assert.equal(sent[0].text.match(/https?:\/\//g).length, 1, 'the portal URL is the only address');
        assert.doesNotMatch(sent[0].text, new RegExp(NEW_PASSWORD), 'never the password');

        // The HTML part says the same, links only to the portal and loads nothing from anywhere
        const { html } = sent[0];
        assert.match(html, /^<!DOCTYPE html>/);
        assert.match(html, /Your password was changed/);
        assert.match(html, /If you did not make this change, contact IT immediately/);
        const links = [...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
        assert.ok(links.length > 0);
        assert.ok(links.every((l) => l === 'https://portal.example.test'), `only the portal is linked: ${links}`);
        assert.doesNotMatch(html, /<img|<script|<link|url\(/i, 'no images, scripts or external resources');
        assert.doesNotMatch(html, new RegExp(NEW_PASSWORD), 'never the password');
        assert.equal(sent[0].headers['Auto-Submitted'], 'auto-generated');
    });

    test('a bare From address gets the portal name as its display name', async () => {
        const settingsService = require('../../server/services/settingsService');
        settingsService.current().mail.from = 'portal@example.test';
        try {
            await changePassword('jsmith', 'Passw0rd!');
            await waitForNotification('jsmith');
            assert.deepEqual(sent[0].from, { name: 'Test Portal', address: 'portal@example.test' });
        } finally {
            await settingsService.refresh();
        }
    });

    test('is mailed after a reset and names the verification method', async () => {
        const { answers } = await enrollUser(api, 'mjones', 'Welcome1!');
        await afterEnrolment('mjones');
        const questions = await api('POST', '/api/password/reset/get-questions', { username: 'mjones' });
        const answerFor = new Map(answers.map((a) => [a.questionId, a.answer]));
        const verified = await api('POST', '/api/password/reset/verify-questions', {
            username: 'mjones',
            answers: questions.body.data.map((q) => ({ questionId: q.id, answer: answerFor.get(q.id) })),
        });
        const res = await api('POST', '/api/password/reset/set-password', {
            resetToken: verified.body.data.resetToken, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD,
        });
        assert.equal(res.status, 200, res.body.message);

        await waitForNotification('mjones');
        assert.equal(sent[0].to, 'mjones@example.local');
        assert.equal(sent[0].subject, 'Your password was reset');
        assert.match(sent[0].text, /Forgot password, verified with security questions/);
    });

    test('enrolling sends a security alert naming the change', async () => {
        await enrollUser(api, 'jsmith', 'Passw0rd!');
        for (let i = 0; i < 50 && sent.length === 0; i++) await new Promise((resolve) => setTimeout(resolve, 20));
        assert.equal(sent.length, 1);
        assert.equal(sent[0].to, 'jsmith@example.local');
        assert.equal(sent[0].subject, 'Your password reset settings changed');
        assert.match(sent[0].text, /enrolled for self-service password reset/);
        assert.match(flat(sent[0].text), /If you did not make this change, contact IT immediately/);
        assert.match(sent[0].html, /What changed/);
    });

    test('is skipped (and audited) when the account has no mail address', async () => {
        await changePassword('primary.only', 'Passw0rd!');
        const audit = await waitForNotification('primary.only');
        assert.match(audit.details, /no mail address/);
        assert.equal(sent.length, 0);
    });

    test('a mail failure does not affect the password change', async () => {
        failSending = true;
        await changePassword('jsmith', 'Passw0rd!');
        const audit = await waitForNotification('jsmith');
        assert.equal(audit.success, false);
        assert.match(audit.details, /Relay refused/);
        await mockAd.authenticateUser('jsmith', NEW_PASSWORD);
    });
});

describe('expiry reminders', () => {
    function expireIn(username, days) {
        mockAd.setAttributes(username, { passwordExpiresAt: new Date(Date.now() + days * DAY_MS - 60 * 1000) });
    }

    test('stages follow the configured days', () => {
        // Default stages: one mail 14 days out, then one per day over the last week
        assert.equal(reminders.currentStage(20), null);
        assert.equal(reminders.currentStage(14), 14);
        assert.equal(reminders.currentStage(10), 14);
        assert.equal(reminders.currentStage(5), 5);
        assert.equal(reminders.currentStage(1), 1);

        // A custom list (as set in the admin panel) is honoured
        const stages = [14, 7, 3, 1];
        assert.equal(reminders.currentStage(10, stages), 14);
        assert.equal(reminders.currentStage(5, stages), 7);
        assert.equal(reminders.currentStage(2, stages), 3);
    });

    test('mails each stage once per expiry date', async () => {
        expireIn('mjones', 5);
        const first = await reminders.runOnce();
        assert.equal(first.sent, 1);
        assert.equal(sent[0].to, 'mjones@example.local');
        assert.equal(sent[0].subject, 'Your password expires in 5 days');
        assert.match(sent[0].text, /https:\/\/portal\.example\.test/);

        assert.equal((await reminders.runOnce()).sent, 0, 'same stage is not mailed twice');

        // Four days later: 1 day left, so the 1-day stage is due
        const later = await reminders.runOnce({ now: new Date(Date.now() + 4 * DAY_MS) });
        assert.equal(later.sent, 1, 'next stage is mailed');
        assert.equal(sent[1].subject, 'Your password expires tomorrow');
    });

    test('skips users far from expiry, without mail, or disabled', async () => {
        mockAd.setAttributes('jsmith', { passwordExpiresAt: new Date(Date.now() + 60 * DAY_MS) });
        mockAd.setAttributes('primary.only', { passwordExpiresAt: new Date(Date.now() + 2 * DAY_MS) });
        mockAd.setAttributes('mjones', { passwordExpiresAt: new Date(Date.now() + 2 * DAY_MS), userAccountControl: '514' });
        expireIn('admin', 0);
        assert.equal((await reminders.runOnce()).sent, 0);
    });

    test('a changed password starts a new cycle', async () => {
        expireIn('jsmith', 2);
        assert.equal((await reminders.runOnce()).sent, 1);
        await changePassword('jsmith', 'Passw0rd!');
        assert.equal((await reminders.runOnce()).due.length, 0, 'new expiry is 90 days away');
    });

    test('a failed mail is retried on the next run', async () => {
        expireIn('jsmith', 2);
        failSending = true;
        assert.equal((await reminders.runOnce()).failed, 1);
        failSending = false;
        assert.equal((await reminders.runOnce()).sent, 1);
    });

    test('dry run reports due users without sending or recording', async () => {
        expireIn('jsmith', 2);
        const dry = await reminders.runOnce({ dryRun: true });
        assert.deepEqual(dry.due.map((u) => u.username), ['jsmith']);
        assert.equal(sent.length, 0);
        assert.equal((await reminders.runOnce()).sent, 1);
    });
});
