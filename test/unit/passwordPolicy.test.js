// Explaining which password policy rule a new password breaks.
require('../helpers/setup');
const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const {
    intervalToDays, normalizePolicy, checkAgainstPolicy, explainRejection, summarize,
} = require('../../server/services/passwordPolicyService');

const DOMAIN = normalizePolicy(
    { minPwdLength: '12', pwdProperties: '1', pwdHistoryLength: '24', minPwdAge: '-864000000000' },
    'domain'
);
const IDENTITY = { username: 'jsmith', displayName: 'John Smith' };

// AD FILETIME for a JS date
function fileTime(date) {
    return String((BigInt(date.getTime()) + 11644473600000n) * 10000n);
}

describe('passwordPolicyService', () => {
    test('reads the domain policy and a fine-grained policy', () => {
        assert.deepEqual(DOMAIN, { source: 'domain', minLength: 12, complexity: true, historyLength: 24, minAgeDays: 1 });
        const pso = normalizePolicy({
            'msDS-MinimumPasswordLength': '15', 'msDS-PasswordComplexityEnabled': 'FALSE',
            'msDS-PasswordHistoryLength': '5', 'msDS-MinimumPasswordAge': '0',
        }, 'fine-grained');
        assert.deepEqual(pso, { source: 'fine-grained', minLength: 15, complexity: false, historyLength: 5, minAgeDays: 0 });
        assert.equal(intervalToDays('-864000000000'), 1);
        assert.equal(intervalToDays('0'), 0);
    });

    test('a password that meets every checkable rule has no problems', () => {
        assert.deepEqual(checkAgainstPolicy('Blue-Harbour-2026', DOMAIN, IDENTITY), []);
    });

    test('each broken rule is named, with the detail', () => {
        const problems = checkAgainstPolicy('jsmith1', DOMAIN, IDENTITY);
        assert.deepEqual(problems.map((p) => p.rule), ['length', 'complexity', 'username']);
        assert.match(problems[0].message, /at least 12 characters \(this one has 7\)/);
        assert.match(problems[1].message, /it has only lowercase letters and numbers/);
        assert.match(problems[2].message, /must not contain your username \(jsmith\)/);
    });

    test('parts of the display name are found, short parts ignored', () => {
        const problems = checkAgainstPolicy('Smith-Garden-2026', DOMAIN, { username: 'jsmith', displayName: 'Jo Smith' });
        assert.deepEqual(problems.map((p) => p.rule), ['name']);
        assert.match(problems[0].message, /a part of your name \(Smith\)/);
    });

    test('without complexity only the length is checked', () => {
        const relaxed = { ...DOMAIN, complexity: false };
        assert.deepEqual(checkAgainstPolicy('correct horse battery staple', relaxed, IDENTITY), []);
    });

    test('an unreadable policy checks nothing (AD still enforces it)', () => {
        assert.deepEqual(checkAgainstPolicy('x', null, IDENTITY), []);
        assert.deepEqual(explainRejection({ policy: null, mode: 'change' }), []);
    });

    test('a refused change within the minimum age says when the next change is possible', () => {
        const now = new Date('2026-11-19T10:00:00Z');
        const [reason] = explainRejection({
            policy: DOMAIN, mode: 'change', pwdLastSet: fileTime(new Date('2026-11-19T08:00:00Z')), now,
        });
        assert.equal(reason.rule, 'min-age');
        assert.match(reason.message, /only after 1 day/);
        assert.match(reason.message, /20 Nov 2026/);
    });

    test('otherwise, and always for a reset, the refusal is put down to the history', () => {
        const old = fileTime(new Date('2026-10-01T08:00:00Z'));
        const now = new Date('2026-11-19T10:00:00Z');
        const [change] = explainRejection({ policy: DOMAIN, mode: 'change', pwdLastSet: old, now });
        assert.equal(change.rule, 'history');
        assert.match(change.message, /one of your last 24 passwords/);
        const [reset] = explainRejection({ policy: DOMAIN, mode: 'reset', pwdLastSet: fileTime(now), now });
        assert.equal(reset.rule, 'history');
    });

    test('the summary names a single problem, or points to the list', () => {
        assert.match(summarize([{ rule: 'length', message: 'Use at least 12 characters (this one has 9).' }]),
            /^The new password does not meet the domain password policy: Use at least 12 characters/);
        assert.match(summarize([{ message: 'a' }, { message: 'b' }]), /fix the points below/);
    });
});
