// Encoding, controls, error mapping and account-state flags for AD password writes.
// Pure (no connection), so it can be unit-tested even though tests run against the mock directory.
const ldap = require('ldapjs');

// LDAP_SERVER_POLICY_HINTS_OID (Windows Server 2012+): makes AD apply password history to a reset
const POLICY_HINTS_OID = '1.2.840.113556.1.4.2239';

// msDS-User-Account-Control-Computed bits
const UF_LOCKOUT = 0x10;
const UF_PASSWORD_EXPIRED = 0x800000;

/** AD wants the password in double quotes, UTF-16LE. */
function encodePassword(password) {
    return Buffer.from(`"${password}"`, 'utf16le');
}

// Value = BER SEQUENCE { INTEGER 1 } (flags: enforce policy). Written through _toBer because the base
// Control turns a Buffer value into a UTF-8 string.
class PolicyHintsControl extends ldap.Control {
    constructor() {
        super({ type: POLICY_HINTS_OID, criticality: true });
    }

    _toBer(ber) {
        ber.writeBuffer(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]), 0x04);
    }
}

/**
 * ldapjs 3.0.7 drops AD's diagnostic text (it reads res.errorMessage, renamed diagnosticMessage), so map by
 * LDAP result code first:
 *   19 constraint violation: policy, history or minimum age (user change; reset sent with policy hints)
 *   53 unwilling to perform: policy failure on a plain reset (0000052D)
 *   50 insufficient access: "User cannot change password", or a protected (adminCount=1) account
 *   12 unavailable critical extension: the DC does not know the policy hints control
 */
function mapPasswordError(err) {
    const message = err?.message || '';
    if (/00000056/.test(message)) return new Error('Current password is incorrect');
    if (err?.code === 19 || err?.code === 53 || /0000052D/i.test(message)) {
        return new Error('Password does not meet the domain password policy requirements');
    }
    if (err?.code === 50) return new Error('Insufficient access rights to change this password');
    if (err?.code === 12) return new Error('The domain controller does not support the password policy hints control');
    return new Error(`Failed to change password: ${message}`);
}

function computedFlags(user) {
    return parseInt(user?.['msDS-User-Account-Control-Computed'], 10) || 0;
}

/**
 * Locked out right now. lockoutTime stays non-zero after the lockout duration ends (until the next successful
 * logon), so the computed attribute is the reliable one; lockoutTime is only the fallback when it is missing.
 */
function isLockedOut(user) {
    if (user?.['msDS-User-Account-Control-Computed'] !== undefined) {
        return (computedFlags(user) & UF_LOCKOUT) !== 0;
    }
    return parseInt(user?.lockoutTime, 10) > 0;
}

/** Password expired, or "User must change password at next logon" (pwdLastSet = 0). */
function isPasswordExpired(user) {
    return String(user?.pwdLastSet) === '0' || (computedFlags(user) & UF_PASSWORD_EXPIRED) !== 0;
}

/** Protected by AdminSDHolder (Domain Admins and similar); the least-privilege account cannot reset it. */
function isProtectedAccount(user) {
    return String(user?.adminCount) === '1';
}

module.exports = {
    POLICY_HINTS_OID,
    PolicyHintsControl,
    encodePassword,
    mapPasswordError,
    isLockedOut,
    isPasswordExpired,
    isProtectedAccount,
};
