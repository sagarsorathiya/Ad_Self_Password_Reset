const ldap = require('ldapjs');
const config = require('../config/default');
const { fileTimeToDate } = require('./adTime');
const {
    PolicyHintsControl, encodePassword, mapPasswordError, isLockedOut, isPasswordExpired,
} = require('./adPassword');

// RFC 4515 escaping for values inside LDAP search filters (prevents LDAP injection)
function escapeFilterValue(value) {
    return String(value).replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

/**
 * Directory operations for one domain.
 * @param {object} ad - Domain settings (config.ad or config.ad.secondary)
 */
function createDirectory(ad) {
    // Result of the last isServiceAccountPrivileged() check (startup): null = not known yet
    let privilegedBind = null;

    /**
     * Create an LDAP client connection.
     * @returns {ldap.Client}
     */
    function createClient() {
        const clientOptions = {
            url: ad.url,
            connectTimeout: 10000,
            timeout: 10000,
        };

        // Add TLS options for LDAPS connections
        if (ad.url.startsWith('ldaps://')) {
            clientOptions.tlsOptions = ad.tlsOptions;
        }

        return ldap.createClient(clientOptions);
    }

    /**
     * Bind (authenticate) to LDAP with given credentials.
     * @param {string} dn - Distinguished name to bind as
     * @param {string} password - Password for the bind
     * @returns {Promise<ldap.Client>} - The bound client
     */
    function bindClient(dn, password) {
        return new Promise((resolve, reject) => {
            const client = createClient();
            const unreachable = (reason) => {
                reject(new Error(`Directory server unreachable: ${reason} (${ad.url})`));
                client.destroy();
            };

            client.on('connectTimeout', () => unreachable('connection timed out'));
            client.on('connectError', (err) => unreachable(err.message));
            client.on('error', (err) => {
                reject(new Error(`LDAP connection error: ${err.message}`));
            });

            const doBind = () => client.bind(dn, password, (err) => {
                if (err) {
                    client.destroy();
                    if (err.code === 49) {
                        reject(new Error('Invalid credentials'));
                    } else {
                        reject(new Error(`LDAP bind failed: ${err.message}`));
                    }
                } else {
                    resolve(client);
                }
            });

            if (!useStartTls()) {
                doBind();
                return;
            }

            // Credentials must never be sent before the TLS upgrade completes
            client.once('connect', () => {
                client.starttls(ad.tlsOptions, [], (err) => {
                    if (err) {
                        client.destroy();
                        reject(new Error(`LDAP connection error: StartTLS failed: ${err.message}`));
                        return;
                    }
                    doBind();
                });
            });
        });
    }

    function useStartTls() {
        return ad.startTls && ad.url.startsWith('ldap://');
    }

    function isEncrypted() {
        return ad.url.startsWith('ldaps://') || useStartTls();
    }

    /**
     * Bind with the service account credentials.
     * @returns {Promise<ldap.Client>}
     */
    async function bindServiceAccount() {
        return bindClient(ad.bindDN, ad.bindPassword);
    }

    /**
     * True if the bind account is protected by AdminSDHolder (adminCount=1), i.e. a member of
     * Domain/Enterprise Admins, Administrators, Account Operators, etc. (including nested).
     */
    async function isServiceAccountPrivileged() {
        const client = await bindServiceAccount();
        try {
            return await new Promise((resolve, reject) => {
                client.search(ad.bindDN, { scope: 'base', attributes: ['adminCount'] }, (err, res) => {
                    if (err) return reject(new Error(`LDAP search failed: ${err.message}`));
                    let privileged = false;
                    res.on('searchEntry', (entry) => {
                        const attr = (entry.pojo?.attributes || entry.attributes || []).find((a) => a.type === 'adminCount');
                        privileged = attr?.values?.[0] === '1';
                    });
                    res.on('error', (e) => reject(new Error(`LDAP search error: ${e.message}`)));
                    res.on('end', () => {
                        privilegedBind = privileged;
                        resolve(privileged);
                    });
                });
            });
        } finally {
            client.unbind(() => {});
        }
    }

    /**
     * Search for a user in AD by sAMAccountName.
     * @param {string} username - sAMAccountName
     * @returns {Promise<object|null>} - User entry or null
     */
    async function findUser(username) {
        const client = await bindServiceAccount();

        try {
            return await new Promise((resolve, reject) => {
                const searchOptions = {
                    scope: 'sub',
                    filter: `(&(objectClass=user)(objectCategory=person)(sAMAccountName=${escapeFilterValue(username)}))`,
                    attributes: [
                        'dn', 'sAMAccountName', 'displayName', 'mail', 'mobile',
                        'userPrincipalName', 'memberOf', 'userAccountControl',
                        'pwdLastSet', 'lockoutTime', 'adminCount', 'msDS-User-Account-Control-Computed',
                        'msDS-UserPasswordExpiryTimeComputed',
                    ],
                };

                client.search(ad.userSearchBase, searchOptions, (err, res) => {
                    if (err) {
                        reject(new Error(`LDAP search failed: ${err.message}`));
                        return;
                    }

                    let user = null;

                    res.on('searchEntry', (entry) => {
                        user = entryAttributes(entry);
                        // null = no expiry date (no maximum age, never expires, or must change at next logon)
                        user.passwordExpiresAt = fileTimeToDate(user['msDS-UserPasswordExpiryTimeComputed']);
                    });

                    res.on('error', (err) => {
                        reject(new Error(`LDAP search error: ${err.message}`));
                    });

                    res.on('end', () => {
                        resolve(user);
                    });
                });
            });
        } finally {
            client.unbind(() => {});
        }
    }

    /**
     * Password expiry of every enabled user with a mail address whose password can expire.
     * Uses AD's computed expiry, so the domain policy and fine-grained password policies apply.
     * @returns {Promise<Array<{dn, username, displayName, mail, adminCount, expiresAt: Date|null}>>}
     *   expiresAt null = no expiry date (e.g. "must change at next logon", or no maximum password age)
     */
    async function listPasswordExpiries() {
        const client = await bindServiceAccount();

        try {
            return await new Promise((resolve, reject) => {
                const searchOptions = {
                    scope: 'sub',
                    // Enabled (UAC bit 2 clear), password can expire (UAC bit 65536 clear), has a mail address
                    filter: '(&(objectCategory=person)(objectClass=user)(mail=*)'
                        + '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
                        + '(!(userAccountControl:1.2.840.113556.1.4.803:=65536)))',
                    attributes: ['sAMAccountName', 'displayName', 'mail', 'adminCount', 'msDS-UserPasswordExpiryTimeComputed'],
                    paged: { pageSize: 500 },
                };

                client.search(ad.userSearchBase, searchOptions, (err, res) => {
                    if (err) {
                        reject(new Error(`LDAP search failed: ${err.message}`));
                        return;
                    }

                    const users = [];
                    res.on('searchEntry', (entry) => {
                        const attrs = entryAttributes(entry);
                        users.push({
                            dn: attrs.dn,
                            username: attrs.sAMAccountName,
                            displayName: attrs.displayName || '',
                            mail: attrs.mail,
                            adminCount: attrs.adminCount,
                            expiresAt: fileTimeToDate(attrs['msDS-UserPasswordExpiryTimeComputed']),
                        });
                    });
                    res.on('error', (e) => reject(new Error(`LDAP search error: ${e.message}`)));
                    res.on('end', () => resolve(users));
                });
            });
        } finally {
            client.unbind(() => {});
        }
    }

    /**
     * Authenticate a user by attempting an LDAP bind with their credentials.
     * @param {string} username - sAMAccountName
     * @param {string} password - User's password
     * @param {object} [options] - { revealState } false = no disabled/locked/expired detail before or after the
     *   bind: every failure is 'Invalid credentials' (security.hideAccountState)
     * @returns {Promise<object>} - User object from AD
     */
    async function authenticateUser(username, password, { revealState = true } = {}) {
        // First, find the user to get their DN
        const user = await findUser(username);
        if (!user) {
            throw new Error('User not found');
        }

        if (revealState) {
            // Check if account is disabled (bit 2 of userAccountControl)
            const uac = parseInt(user.userAccountControl, 10);
            if (uac && (uac & 2) !== 0) {
                throw new Error('Account is disabled');
            }
            if (isLockedOut(user)) {
                throw new Error('Account is locked out');
            }
        }

        // Attempt bind with user's credentials
        let userClient;
        try {
            userClient = await bindClient(user.dn, password);
        } catch (err) {
            // AD refuses the bind for an expired or "must change" password even when it is correct
            if (revealState && err.message === 'Invalid credentials' && isPasswordExpired(user)) {
                throw new Error('Password expired');
            }
            throw err;
        }
        userClient.unbind(() => {});

        return user;
    }

    /**
     * Set a user's password with the service account ("Reset Password" right), e.g. after a verified reset.
     * With resetPolicyHints (default) the LDAP_SERVER_POLICY_HINTS control makes AD apply password history too.
     * @param {string} userDN - The user's distinguished name
     * @param {string} newPassword - The new password
     * @returns {Promise<void>}
     */
    async function changePassword(userDN, newPassword) {
        if (!isEncrypted()) {
            throw new Error('LDAP connection error: password changes require LDAPS or AD_STARTTLS=true');
        }

        const client = await bindServiceAccount();

        try {
            const change = new ldap.Change({
                operation: 'replace',
                modification: new ldap.Attribute({ type: 'unicodePwd', values: [encodePassword(newPassword)] }),
            });
            const controls = ad.resetPolicyHints ? [new PolicyHintsControl()] : [];

            // Must await: the finally block would otherwise close the connection before AD replies
            return await new Promise((resolve, reject) => {
                client.modify(userDN, change, controls, (err) => (err ? reject(mapPasswordError(err)) : resolve()));
            });
        } finally {
            client.unbind(() => {});
        }
    }

    /**
     * Authenticated change. By default a real user change: bound as the user, one modify that deletes the old
     * unicodePwd value and adds the new one, so AD enforces history and minimum password age.
     * AD_USER_PASSWORD_CHANGE=false restores the old path (verify by bind, then a service-account reset).
     * @param {string} userDN - User's DN
     * @param {string} oldPassword - Current password
     * @param {string} newPassword - New password
     * @returns {Promise<void>}
     */
    async function changePasswordWithOld(userDN, oldPassword, newPassword) {
        if (!ad.userPasswordChange) {
            const check = await bindClient(userDN, oldPassword); // throws 'Invalid credentials'
            check.unbind(() => {});
            return changePassword(userDN, newPassword);
        }
        if (!isEncrypted()) {
            throw new Error('LDAP connection error: password changes require LDAPS or AD_STARTTLS=true');
        }

        // StartTLS (when configured) completes inside bindClient before the password is sent
        const client = await bindClient(userDN, oldPassword); // throws 'Invalid credentials'
        try {
            const changes = [
                new ldap.Change({
                    operation: 'delete',
                    modification: new ldap.Attribute({ type: 'unicodePwd', values: [encodePassword(oldPassword)] }),
                }),
                new ldap.Change({
                    operation: 'add',
                    modification: new ldap.Attribute({ type: 'unicodePwd', values: [encodePassword(newPassword)] }),
                }),
            ];
            return await new Promise((resolve, reject) => {
                client.modify(userDN, changes, (err) => (err ? reject(mapPasswordError(err)) : resolve()));
            });
        } finally {
            client.unbind(() => {});
        }
    }

    /**
     * Attributes of one object (base search), or null when it does not exist or cannot be read.
     * @param {string} dn
     * @param {string[]} attributes
     */
    async function readObject(dn, attributes) {
        const client = await bindServiceAccount();
        try {
            return await new Promise((resolve, reject) => {
                client.search(dn, { scope: 'base', filter: '(objectClass=*)', attributes }, (err, res) => {
                    if (err) {
                        reject(new Error(`LDAP search failed: ${err.message}`));
                        return;
                    }
                    let found = null;
                    res.on('searchEntry', (entry) => { found = entryAttributes(entry); });
                    res.on('error', (e) => reject(new Error(`LDAP search error: ${e.message}`)));
                    res.on('end', () => resolve(found));
                });
            });
        } finally {
            client.unbind(() => {});
        }
    }

    /**
     * The default domain password policy, read from the domain root (AD_BASE_DN).
     * @returns {Promise<object|null>} minPwdLength, pwdProperties, pwdHistoryLength, minPwdAge
     */
    async function getDomainPasswordPolicy() {
        return readObject(ad.baseDN, ['minPwdLength', 'pwdProperties', 'pwdHistoryLength', 'minPwdAge']);
    }

    /**
     * The fine-grained password policy (PSO) that applies to this user, or null when the domain policy applies.
     * msDS-ResultantPSO is a constructed attribute (base search on the user only); reading the PSO itself needs
     * read access to the Password Settings Container (Domain Admins by default) - without it, null.
     * @param {string} userDN
     */
    async function getResultantPasswordPolicy(userDN) {
        const user = await readObject(userDN, ['msDS-ResultantPSO']);
        const psoDN = user?.['msDS-ResultantPSO'];
        if (!psoDN) return null;
        return readObject(psoDN, [
            'msDS-MinimumPasswordLength', 'msDS-PasswordComplexityEnabled',
            'msDS-PasswordHistoryLength', 'msDS-MinimumPasswordAge',
        ]);
    }

    /**
     * Clear an AD lockout (lockoutTime = 0). Needs "Write lockoutTime" on user objects for the service account.
     * @param {string} userDN
     */
    async function unlockAccount(userDN) {
        const client = await bindServiceAccount();
        try {
            const change = new ldap.Change({
                operation: 'replace',
                modification: new ldap.Attribute({ type: 'lockoutTime', values: ['0'] }),
            });
            return await new Promise((resolve, reject) => {
                client.modify(userDN, change, (err) => (err ? reject(new Error(`Unlock failed: ${err.message}`)) : resolve()));
            });
        } finally {
            client.unbind(() => {});
        }
    }

    /**
     * Every user account in one paged search, for the reminder run (instead of one bind per account).
     * @returns {Promise<Map<string, {sAMAccountName, displayName, mail, userAccountControl}>>} keyed by lower-case name
     */
    async function listSignInAccounts() {
        const client = await bindServiceAccount();
        try {
            return await new Promise((resolve, reject) => {
                const searchOptions = {
                    scope: 'sub',
                    filter: '(&(objectCategory=person)(objectClass=user))',
                    attributes: ['sAMAccountName', 'displayName', 'mail', 'userAccountControl'],
                    paged: { pageSize: 500 },
                };
                client.search(ad.userSearchBase, searchOptions, (err, res) => {
                    if (err) {
                        reject(new Error(`LDAP search failed: ${err.message}`));
                        return;
                    }
                    const accounts = new Map();
                    res.on('searchEntry', (entry) => {
                        const attrs = entryAttributes(entry);
                        if (!attrs.sAMAccountName) return;
                        accounts.set(String(attrs.sAMAccountName).toLowerCase(), {
                            sAMAccountName: attrs.sAMAccountName,
                            displayName: attrs.displayName || '',
                            mail: attrs.mail || '',
                            userAccountControl: attrs.userAccountControl,
                        });
                    });
                    res.on('error', (e) => reject(new Error(`LDAP search error: ${e.message}`)));
                    res.on('end', () => resolve(accounts));
                });
            });
        } finally {
            client.unbind(() => {});
        }
    }

    return {
        name: ad.name,
        findUser,
        authenticateUser,
        changePassword,
        changePasswordWithOld,
        unlockAccount,
        getDomainPasswordPolicy,
        getResultantPasswordPolicy,
        listPasswordExpiries,
        listSignInAccounts,
        isServiceAccountPrivileged,
        // true/false once the startup check ran: a privileged bind account CAN reset protected accounts
        serviceAccountPrivileged: () => privilegedBind,
    };
}

// Search entry → { dn, attribute: value | [values] }
function entryAttributes(entry) {
    const attrs = {};
    // ldapjs v3 returns pojo entries
    if (entry.pojo) {
        entry.pojo.attributes.forEach(attr => {
            attrs[attr.type] = attr.values.length === 1 ? attr.values[0] : attr.values;
        });
        attrs.dn = entry.pojo.objectName;
    } else {
        // Fallback for older versions
        attrs.dn = entry.objectName || entry.dn?.toString();
        for (const attr of entry.attributes || []) {
            const vals = attr.values || attr._vals?.map(v => v.toString());
            attrs[attr.type] = vals?.length === 1 ? vals[0] : vals;
        }
    }
    return attrs;
}

/**
 * Check if a user is a member of the admin group.
 * @param {object} user - User object from AD (must have memberOf attribute)
 * @returns {boolean}
 */
function isAdmin(user) {
    if (!user.memberOf) return false;

    const groups = Array.isArray(user.memberOf) ? user.memberOf : [user.memberOf];
    const adminGroupDN = config.ad.adminGroup.toLowerCase();

    return groups.some(g => g.toLowerCase() === adminGroupDN);
}

function createSecondary(ad) {
    if (!ad) return null;
    if (ad.mode === 'windows') {
        return require('./windowsDirectoryService').createWindowsDirectory(ad, escapeFilterValue);
    }
    return createDirectory(ad);
}

module.exports = config.ad.mock
    ? require('./mockLdapService')
    : {
        ...createDirectory(config.ad),
        isAdmin,
        // Second domain kept in sync on every password change/reset (null when AD2_URL is unset)
        secondary: createSecondary(config.ad.secondary),
    };
