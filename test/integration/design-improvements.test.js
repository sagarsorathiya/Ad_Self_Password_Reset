// Dashboard account status, sign-in domain prefix and the domain name on change/reset responses.
// Must be set before setup loads config.
process.env.AD_BASE_DN = 'DC=corp,DC=example';
delete process.env.AD_SIGNIN_DOMAIN;
process.env.AD2_URL = 'ldaps://dc.second.example.test:636';
process.env.AD2_USER_SEARCH_BASE = 'OU=Users,DC=second,DC=example,DC=test';
process.env.AD2_DOMAIN_LABEL = 'Mail';
process.env.AD_DOMAIN_LABEL = 'Desktop';

const { startServer, resetState, login, enrollUser } = require('../helpers/setup');
const { describe, test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const DAY_MS = 24 * 60 * 60 * 1000;

let server;
let api;
let mockAd;
let config;
let settingsService;
let authController;

before(async () => {
    server = await startServer();
    api = server.request;
    mockAd = require('../../server/services/mockLdapService');
    config = require('../../server/config/default');
    settingsService = require('../../server/services/settingsService');
    authController = require('../../server/controllers/authController');
});
after(() => server?.close());
beforeEach(async () => {
    await resetState();
    authController._clearExpiryCache();
    settingsService.current().reminders.source = 'primary';
});

describe('GET /api/auth/account-status', () => {
    test('needs a signed-in user', async () => {
        const res = await api('GET', '/api/auth/account-status');
        assert.equal(res.status, 401);
    });

    test('reports the first-domain expiry, the policy and the factors', async () => {
        mockAd.setAttributes('jsmith', { passwordExpiresAt: new Date(Date.now() + 12 * DAY_MS - 60 * 1000) });
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await api('GET', '/api/auth/account-status', undefined, token);
        assert.equal(res.status, 200, res.body.message);
        const { passwordExpiry, resetPolicy, factors, domain } = res.body.data;
        assert.equal(passwordExpiry.daysLeft, 12);
        assert.equal(passwordExpiry.domain, 'Desktop');
        assert.equal(passwordExpiry.neverExpires, false);
        assert.ok(Date.parse(passwordExpiry.expiresAt) > Date.now());
        assert.equal(resetPolicy, 'either');
        assert.equal(typeof factors.totp, 'boolean');
        assert.equal(domain, 'Desktop');
    });

    test('no expiry date reads as never expires', async () => {
        mockAd.setAttributes('mjones', { passwordExpiresAt: null });
        const { token } = await enrollUser(api, 'mjones', 'Welcome1!');
        const res = await api('GET', '/api/auth/account-status', undefined, token);
        assert.equal(res.status, 200);
        assert.equal(res.body.data.passwordExpiry.neverExpires, true);
        assert.equal(res.body.data.passwordExpiry.expiresAt, null);
    });

    test('reads the second domain when reminders use it', async () => {
        mockAd.secondary.setAttributes('jsmith', { passwordExpiresAt: new Date(Date.now() + 3 * DAY_MS - 60 * 1000) });
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        settingsService.current().reminders.source = 'secondary';
        const res = await api('GET', '/api/auth/account-status', undefined, token);
        assert.equal(res.status, 200);
        assert.equal(res.body.data.passwordExpiry.daysLeft, 3);
        assert.equal(res.body.data.passwordExpiry.domain, 'Mail');
    });

    test('a user missing from the second domain gets no expiry', async () => {
        const { token } = await enrollUser(api, 'primary.only', 'Passw0rd!');
        settingsService.current().reminders.source = 'secondary';
        const res = await api('GET', '/api/auth/account-status', undefined, token);
        assert.equal(res.status, 200);
        assert.equal(res.body.data.passwordExpiry, null);
    });

    test('an unreachable directory still answers 200 without the expiry', async () => {
        const { token } = await login(api, 'jsmith', 'Passw0rd!');
        mockAd.setUnavailable(true);
        try {
            const res = await api('GET', '/api/auth/account-status', undefined, token);
            assert.equal(res.status, 200);
            assert.equal(res.body.data.passwordExpiry, null);
        } finally {
            mockAd.setUnavailable(false);
        }
    });
});

describe('GET /api/auth/sign-in-info', () => {
    test('derives the prefix from the base DN without a sign-in', async () => {
        const res = await api('GET', '/api/auth/sign-in-info');
        assert.equal(res.status, 200);
        assert.equal(res.body.data.domainPrefix, 'CORP');
    });

    test('an empty setting (AD_SIGNIN_DOMAIN=none) gives no prefix', async () => {
        const saved = config.ad.signInDomain;
        config.ad.signInDomain = '';
        try {
            const res = await api('GET', '/api/auth/sign-in-info');
            assert.equal(res.body.data.domainPrefix, null);
        } finally {
            config.ad.signInDomain = saved;
        }
    });
});

describe('change and reset responses name the domain', () => {
    test('change returns data.domain', async () => {
        const { token } = await enrollUser(api, 'jsmith', 'Passw0rd!');
        const res = await api('POST', '/api/password/change', {
            currentPassword: 'Passw0rd!', newPassword: 'Brand-New-Pass1', confirmPassword: 'Brand-New-Pass1',
        }, token);
        assert.equal(res.status, 200, res.body.message);
        assert.equal(res.body.data.domain, 'Desktop');
        assert.equal(res.body.data.sync.status, 'synced');
    });

    test('reset returns data.domain', async () => {
        const { answers } = await enrollUser(api, 'mjones', 'Welcome1!');
        const questions = await api('POST', '/api/password/reset/get-questions', { username: 'mjones' });
        const answerFor = new Map(answers.map((a) => [a.questionId, a.answer]));
        const verified = await api('POST', '/api/password/reset/verify-questions', {
            username: 'mjones',
            answers: questions.body.data.map((q) => ({ questionId: q.id, answer: answerFor.get(q.id) })),
        });
        assert.equal(verified.status, 200, verified.body.message);
        const res = await api('POST', '/api/password/reset/set-password', {
            resetToken: verified.body.data.resetToken, newPassword: 'Brand-New-Pass1', confirmPassword: 'Brand-New-Pass1',
        });
        assert.equal(res.status, 200, res.body.message);
        assert.equal(res.body.data.domain, 'Desktop');
        assert.equal(res.body.data.unlocked, false);
    });
});
