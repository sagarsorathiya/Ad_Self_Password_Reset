// In-memory stand-in for Active Directory. Mirrors the ldapService interface and error messages.
const config = require('../config/default');
const { isLockedOut, isPasswordExpired } = require('./adPassword');

const PASSWORD_HISTORY = 3;
const UAC_ACCOUNT_DISABLED = 2;
const DAY_MS = 24 * 60 * 60 * 1000;
// Like a 90-day domain password policy
const MAX_PASSWORD_AGE_MS = 90 * DAY_MS;

const SEED_USERS = [
    { username: 'jsmith', password: 'Passw0rd!', displayName: 'John Smith', mail: 'jsmith@example.local', mobile: '+919876500001' },
    { username: 'mjones', password: 'Welcome1!', displayName: 'Mary Jones', mail: 'mjones@example.local' },
    { username: 'admin', password: 'Adm1nPass!', displayName: 'Portal Admin', mail: 'admin@example.local', admin: true },
    { username: 'disabled.user', password: 'Passw0rd!', displayName: 'Disabled User', userAccountControl: 514 },
    { username: 'locked.user', password: 'Passw0rd!', displayName: 'Locked Out User', lockoutTime: '133000000000000000', lockedOut: true },
    // Lockout duration has passed: lockoutTime is still set (as in AD until the next logon), the computed flag is not
    { username: 'was.locked', password: 'Passw0rd!', displayName: 'Formerly Locked User', lockoutTime: '133000000000000000' },
    // "User must change password at next logon"
    { username: 'expired.user', password: 'Passw0rd!', displayName: 'Expired Password User', mail: 'expired.user@example.local', mustChange: true },
    // Exists only in the first domain (exercises the "not in the second domain" path)
    { username: 'primary.only', password: 'Passw0rd!', displayName: 'Primary Only User', primaryOnly: true },
    // Exists only in the second domain (must never get a reminder: cannot sign in to the portal)
    { username: 'secondary.only', password: 'Passw0rd!', displayName: 'Secondary Only User', mail: 'secondary.only@example.local', secondaryOnly: true },
];

// Approximates the default AD policy: length, 3 of 4 categories, no sAMAccountName, history.
function checkPolicy(record, newPassword) {
    const categories = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(newPassword)).length;
    const containsName = newPassword.toLowerCase().includes(record.entry.sAMAccountName.toLowerCase());
    if (newPassword.length < 8 || categories < 3 || containsName || record.history.includes(newPassword)) {
        throw new Error('Password does not meet the domain password policy requirements');
    }
}

// AD FILETIME (100-ns units since 1601) for a JS date, as stored in pwdLastSet
function toFileTime(date = new Date()) {
    return String((BigInt(date.getTime()) + 11644473600000n) * 10000n);
}

// Domain password policy as AD stores it on the domain root (minPwdAge: negative 100-ns units)
const DEFAULT_POLICY = { minPwdLength: '8', pwdProperties: '1', pwdHistoryLength: String(PASSWORD_HISTORY), minPwdAge: '0' };

function isAdmin(user) {
    if (!user.memberOf) return false;
    const groups = Array.isArray(user.memberOf) ? user.memberOf : [user.memberOf];
    const adminGroupDN = config.ad.adminGroup.toLowerCase();
    return groups.some((g) => g.toLowerCase() === adminGroupDN);
}

/**
 * One in-memory domain.
 * @param {object} options - { name, searchBase, secondary }
 */
function createMockDirectory({ name, searchBase, secondary = false }) {
    let directory = new Map();
    // Tests flip this to simulate a domain controller that cannot be reached
    let unavailable = false;
    // Tests read these to check that bulk operations do not fall back to one lookup per account
    const calls = { findUser: 0 };

    function ensureAvailable() {
        if (unavailable) throw new Error(`Directory server unreachable: connection timed out (mock ${name})`);
    }

    function reset() {
        unavailable = false;
        protectedResetRefused = false;
        policy = { ...DEFAULT_POLICY };
        calls.findUser = 0;
        directory = new Map();
        for (const seed of SEED_USERS) {
            if (secondary && seed.primaryOnly) continue;
            if (!secondary && seed.secondaryOnly) continue;
            const dn = `CN=${seed.displayName},${searchBase}`;
            directory.set(seed.username.toLowerCase(), {
                entry: {
                    dn,
                    sAMAccountName: seed.username,
                    displayName: seed.displayName,
                    mail: seed.mail || '',
                    // Only some accounts carry a mobile number, like a real directory
                    mobile: seed.mobile || '',
                    userPrincipalName: `${seed.username}@example.local`,
                    memberOf: seed.admin && !secondary ? [config.ad.adminGroup] : [],
                    userAccountControl: String(seed.userAccountControl || 512),
                    lockoutTime: seed.lockoutTime || '0',
                    'msDS-User-Account-Control-Computed': seed.lockedOut ? '16' : '0',
                    pwdLastSet: seed.mustChange ? '0' : '133000000000000000',
                    adminCount: seed.admin ? '1' : undefined,
                    // Stands in for msDS-UserPasswordExpiryTimeComputed (null = no expiry date)
                    passwordExpiresAt: new Date(Date.now() + 60 * DAY_MS),
                },
                password: seed.password,
                history: [seed.password],
            });
        }
    }

    function findRecordByDn(dn) {
        for (const record of directory.values()) {
            if (record.entry.dn.toLowerCase() === String(dn).toLowerCase()) return record;
        }
        return null;
    }

    async function findUser(username) {
        ensureAvailable();
        calls.findUser++;
        const record = directory.get(String(username || '').toLowerCase());
        return record ? { ...record.entry, memberOf: [...record.entry.memberOf] } : null;
    }

    // Same order and messages as ldapService.authenticateUser
    async function authenticateUser(username, password, { revealState = true } = {}) {
        ensureAvailable();
        const record = directory.get(String(username || '').toLowerCase());
        if (!record) throw new Error('User not found');

        const uac = parseInt(record.entry.userAccountControl, 10);
        const disabled = (uac & UAC_ACCOUNT_DISABLED) !== 0;
        if (revealState && disabled) throw new Error('Account is disabled');
        if (revealState && isLockedOut(record.entry)) throw new Error('Account is locked out');
        // AD refuses the bind for disabled, locked-out and expired accounts even with the right password
        const bindFails = disabled || isLockedOut(record.entry) || isPasswordExpired(record.entry);
        if (record.password !== password || bindFails) {
            if (revealState && isPasswordExpired(record.entry)) throw new Error('Password expired');
            throw new Error('Invalid credentials');
        }

        record.entry.lockoutTime = '0';
        return findUser(username);
    }

    async function changePassword(userDN, newPassword) {
        ensureAvailable();
        const record = findRecordByDn(userDN);
        if (!record) throw new Error('Failed to change password: no such object');

        if (record.entry.adminCount === '1' && protectedResetRefused) {
            throw new Error('Insufficient access rights to change this password');
        }
        checkPolicy(record, newPassword);
        record.password = newPassword;
        record.entry.pwdLastSet = toFileTime();
        record.history = [newPassword, ...record.history].slice(0, PASSWORD_HISTORY);
        record.entry.passwordExpiresAt = new Date(Date.now() + MAX_PASSWORD_AGE_MS);
    }

    // A user change runs with the user's own rights, so protected accounts may change their own password
    async function changePasswordWithOld(userDN, oldPassword, newPassword) {
        ensureAvailable();
        const record = findRecordByDn(userDN);
        if (!record || record.password !== oldPassword) throw new Error('Invalid credentials');
        // Minimum password age applies to a change by the user (not to an admin reset)
        const minAgeMs = Math.abs(Number(policy.minPwdAge)) / 10000;
        const lastSetMs = Number(BigInt(record.entry.pwdLastSet || '0') / 10000n) - 11644473600000;
        if (minAgeMs > 0 && Date.now() - lastSetMs < minAgeMs) {
            throw new Error('Password does not meet the domain password policy requirements');
        }
        checkPolicy(record, newPassword);
        record.password = newPassword;
        record.entry.pwdLastSet = toFileTime();
        record.history = [newPassword, ...record.history].slice(0, PASSWORD_HISTORY);
        record.entry.passwordExpiresAt = new Date(Date.now() + MAX_PASSWORD_AGE_MS);
    }

    async function unlockAccount(userDN) {
        ensureAvailable();
        const record = findRecordByDn(userDN);
        if (!record) throw new Error('Unlock failed: no such object');
        record.entry.lockoutTime = '0';
        record.entry['msDS-User-Account-Control-Computed'] = '0';
    }

    async function listSignInAccounts() {
        ensureAvailable();
        const accounts = new Map();
        for (const record of directory.values()) {
            const e = record.entry;
            accounts.set(e.sAMAccountName.toLowerCase(), {
                sAMAccountName: e.sAMAccountName,
                displayName: e.displayName,
                mail: e.mail,
                userAccountControl: e.userAccountControl,
            });
        }
        return accounts;
    }

    async function listPasswordExpiries() {
        ensureAvailable();
        return [...directory.values()]
            .map((record) => record.entry)
            .filter((e) => e.mail && (parseInt(e.userAccountControl, 10) & UAC_ACCOUNT_DISABLED) === 0)
            .map((e) => ({
                dn: e.dn,
                username: e.sAMAccountName,
                displayName: e.displayName,
                mail: e.mail,
                adminCount: e.adminCount,
                expiresAt: e.passwordExpiresAt,
            }));
    }

    // Real AD refuses a service-account reset of an adminCount=1 account; tests switch this on to see it
    let protectedResetRefused = false;
    // Domain policy (tests change it with setPasswordPolicy; reset() restores it)
    let policy = { ...DEFAULT_POLICY };

    async function getDomainPasswordPolicy() {
        ensureAvailable();
        return { ...policy };
    }

    reset();

    return {
        name,
        calls,
        findUser,
        authenticateUser,
        changePassword,
        changePasswordWithOld,
        unlockAccount,
        getDomainPasswordPolicy,
        // No fine-grained policies in the mock: the domain policy always applies
        getResultantPasswordPolicy: async () => null,
        setPasswordPolicy: (overrides) => { policy = { ...policy, ...overrides }; },
        listSignInAccounts,
        listPasswordExpiries,
        setProtectedResetRefused: (value) => { protectedResetRefused = Boolean(value); },
        isServiceAccountPrivileged: async () => false,
        serviceAccountPrivileged: () => false,
        reset,
        setUnavailable: (value) => { unavailable = Boolean(value); },
        // Tests only: change stored attributes (e.g. userAccountControl); reset() restores the seed
        setAttributes: (username, attributes) => {
            Object.assign(directory.get(String(username).toLowerCase()).entry, attributes);
        },
    };
}

const primary = createMockDirectory({ name: config.ad.name, searchBase: config.ad.userSearchBase });
const secondary = config.ad.secondary
    ? createMockDirectory({ name: config.ad.secondary.name, searchBase: config.ad.secondary.userSearchBase, secondary: true })
    : null;

module.exports = {
    ...primary,
    isAdmin,
    secondary,
    reset() {
        primary.reset();
        secondary?.reset();
    },
    seedUsers: SEED_USERS.map(({ username, password }) => ({ username, password })),
};
