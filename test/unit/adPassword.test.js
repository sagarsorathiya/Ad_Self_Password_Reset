// AD password-write helpers: the policy hints control, error mapping and account-state flags.
require('../helpers/setup');
const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const {
    PolicyHintsControl, encodePassword, mapPasswordError, isLockedOut, isPasswordExpired, isProtectedAccount,
} = require('../../server/services/adPassword');

describe('adPassword', () => {
    test('the policy hints control encodes as SEQUENCE { OID, critical, OCTET STRING { SEQUENCE { INTEGER 1 } } }', () => {
        // Checked against ldapjs 3.0.7: the value must go out as raw bytes, not as a UTF-8 string
        assert.equal(
            new PolicyHintsControl().toBer().buffer.toString('hex'),
            '30230417312e322e3834302e3131333535362e312e342e323233390101ff04053003020101'
        );
    });

    test('passwords are quoted and UTF-16LE encoded', () => {
        assert.deepEqual(encodePassword('a'), Buffer.from('"a"', 'utf16le'));
    });

    test('LDAP result codes map to the messages the controllers handle', () => {
        assert.match(mapPasswordError({ code: 19 }).message, /password policy/);
        assert.match(mapPasswordError({ code: 53 }).message, /password policy/);
        assert.match(mapPasswordError({ message: '0000052D: Constraint violation' }).message, /password policy/);
        assert.equal(mapPasswordError({ message: 'x 00000056 y' }).message, 'Current password is incorrect');
        assert.match(mapPasswordError({ code: 50 }).message, /^Insufficient access rights/);
        assert.match(mapPasswordError({ code: 12 }).message, /does not support the password policy hints/);
        assert.equal(mapPasswordError({ code: 1, message: 'Operations Error' }).message, 'Failed to change password: Operations Error');
    });

    test('a lockout counts only while the computed flag says so', () => {
        // lockoutTime stays set after the lockout duration until the next logon
        assert.equal(isLockedOut({ lockoutTime: '133000000000000000', 'msDS-User-Account-Control-Computed': '0' }), false);
        assert.equal(isLockedOut({ lockoutTime: '133000000000000000', 'msDS-User-Account-Control-Computed': '16' }), true);
        // Without the computed attribute, lockoutTime is the fallback
        assert.equal(isLockedOut({ lockoutTime: '133000000000000000' }), true);
        assert.equal(isLockedOut({ lockoutTime: '0' }), false);
    });

    test('expired and "must change" passwords are recognised', () => {
        assert.equal(isPasswordExpired({ pwdLastSet: '0' }), true);
        assert.equal(isPasswordExpired({ pwdLastSet: '133000000000000000', 'msDS-User-Account-Control-Computed': String(0x800000) }), true);
        assert.equal(isPasswordExpired({ pwdLastSet: '133000000000000000', 'msDS-User-Account-Control-Computed': '0' }), false);
    });

    test('adminCount=1 marks a protected account', () => {
        assert.equal(isProtectedAccount({ adminCount: '1' }), true);
        assert.equal(isProtectedAccount({ adminCount: undefined }), false);
    });
});
