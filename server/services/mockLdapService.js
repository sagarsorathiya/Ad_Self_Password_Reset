// In-memory stand-in for Active Directory. Mirrors the ldapService interface and error messages.
const config = require('../config/default');

const PASSWORD_HISTORY = 3;
const UAC_ACCOUNT_DISABLED = 2;

const SEED_USERS = [
    { username: 'jsmith', password: 'Passw0rd!', displayName: 'John Smith', mail: 'jsmith@example.local' },
    { username: 'mjones', password: 'Welcome1!', displayName: 'Mary Jones', mail: 'mjones@example.local' },
    { username: 'admin', password: 'Adm1nPass!', displayName: 'Portal Admin', mail: 'admin@example.local', admin: true },
    { username: 'disabled.user', password: 'Passw0rd!', displayName: 'Disabled User', userAccountControl: 514 },
    { username: 'locked.user', password: 'Passw0rd!', displayName: 'Locked Out User', lockoutTime: '133000000000000000' },
    // Exists only in the first domain (exercises the "not in the second domain" path)
    { username: 'primary.only', password: 'Passw0rd!', displayName: 'Primary Only User', primaryOnly: true },
];

// Approximates the default AD policy: length, 3 of 4 categories, no sAMAccountName, history.
function checkPolicy(record, newPassword) {
    const categories = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(newPassword)).length;
    const containsName = newPassword.toLowerCase().includes(record.entry.sAMAccountName.toLowerCase());
    if (newPassword.length < 8 || categories < 3 || containsName || record.history.includes(newPassword)) {
        throw new Error('Password does not meet the domain password policy requirements');
    }
}

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

    function ensureAvailable() {
        if (unavailable) throw new Error(`Directory server unreachable: connection timed out (mock ${name})`);
    }

    function reset() {
        unavailable = false;
        directory = new Map();
        for (const seed of SEED_USERS) {
            if (secondary && seed.primaryOnly) continue;
            const dn = `CN=${seed.displayName},${searchBase}`;
            directory.set(seed.username.toLowerCase(), {
                entry: {
                    dn,
                    sAMAccountName: seed.username,
                    displayName: seed.displayName,
                    mail: seed.mail || '',
                    userPrincipalName: `${seed.username}@example.local`,
                    memberOf: seed.admin && !secondary ? [config.ad.adminGroup] : [],
                    userAccountControl: String(seed.userAccountControl || 512),
                    lockoutTime: seed.lockoutTime || '0',
                    adminCount: seed.admin ? '1' : undefined,
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
        const record = directory.get(String(username || '').toLowerCase());
        return record ? { ...record.entry, memberOf: [...record.entry.memberOf] } : null;
    }

    async function authenticateUser(username, password) {
        ensureAvailable();
        const record = directory.get(String(username || '').toLowerCase());
        if (!record) throw new Error('User not found');

        const uac = parseInt(record.entry.userAccountControl, 10);
        if ((uac & UAC_ACCOUNT_DISABLED) !== 0) throw new Error('Account is disabled');
        if (parseInt(record.entry.lockoutTime, 10) > 0) throw new Error('Account is locked out');
        if (record.password !== password) throw new Error('Invalid credentials');

        return findUser(username);
    }

    async function changePassword(userDN, newPassword) {
        ensureAvailable();
        const record = findRecordByDn(userDN);
        if (!record) throw new Error('Failed to change password: no such object');

        checkPolicy(record, newPassword);
        record.password = newPassword;
        record.history = [newPassword, ...record.history].slice(0, PASSWORD_HISTORY);
    }

    async function changePasswordWithOld(userDN, oldPassword, newPassword) {
        ensureAvailable();
        const record = findRecordByDn(userDN);
        if (!record || record.password !== oldPassword) throw new Error('Invalid credentials');
        await changePassword(userDN, newPassword);
    }

    reset();

    return {
        name,
        findUser,
        authenticateUser,
        changePassword,
        changePasswordWithOld,
        isServiceAccountPrivileged: async () => false,
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
