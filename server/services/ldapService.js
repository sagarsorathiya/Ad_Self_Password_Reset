const ldap = require('ldapjs');
const config = require('../config/default');

/**
 * Create an LDAP client connection.
 * @returns {ldap.Client}
 */
function createClient() {
    const clientOptions = {
        url: config.ad.url,
        connectTimeout: 10000,
        timeout: 10000,
    };

    // Add TLS options for LDAPS connections
    if (config.ad.url.startsWith('ldaps://')) {
        clientOptions.tlsOptions = config.ad.tlsOptions;
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
            reject(new Error(`Directory server unreachable: ${reason} (${config.ad.url})`));
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
            client.starttls(config.ad.tlsOptions, [], (err) => {
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
    return config.ad.startTls && config.ad.url.startsWith('ldap://');
}

function isEncrypted() {
    return config.ad.url.startsWith('ldaps://') || useStartTls();
}

// RFC 4515 escaping for values inside LDAP search filters (prevents LDAP injection)
function escapeFilterValue(value) {
    return String(value).replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

/**
 * Bind with the service account credentials.
 * @returns {Promise<ldap.Client>}
 */
async function bindServiceAccount() {
    return bindClient(config.ad.bindDN, config.ad.bindPassword);
}

/**
 * True if the bind account is protected by AdminSDHolder (adminCount=1), i.e. a member of
 * Domain/Enterprise Admins, Administrators, Account Operators, etc. (including nested).
 */
async function isServiceAccountPrivileged() {
    const client = await bindServiceAccount();
    try {
        return await new Promise((resolve, reject) => {
            client.search(config.ad.bindDN, { scope: 'base', attributes: ['adminCount'] }, (err, res) => {
                if (err) return reject(new Error(`LDAP search failed: ${err.message}`));
                let privileged = false;
                res.on('searchEntry', (entry) => {
                    const attr = (entry.pojo?.attributes || entry.attributes || []).find((a) => a.type === 'adminCount');
                    privileged = attr?.values?.[0] === '1';
                });
                res.on('error', (e) => reject(new Error(`LDAP search error: ${e.message}`)));
                res.on('end', () => resolve(privileged));
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
                    'dn', 'sAMAccountName', 'displayName', 'mail',
                    'userPrincipalName', 'memberOf', 'userAccountControl',
                    'pwdLastSet', 'lockoutTime',
                ],
            };

            client.search(config.ad.userSearchBase, searchOptions, (err, res) => {
                if (err) {
                    reject(new Error(`LDAP search failed: ${err.message}`));
                    return;
                }

                let user = null;

                res.on('searchEntry', (entry) => {
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
                    user = attrs;
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
 * Authenticate a user by attempting an LDAP bind with their credentials.
 * @param {string} username - sAMAccountName
 * @param {string} password - User's password
 * @returns {Promise<object>} - User object from AD
 */
async function authenticateUser(username, password) {
    // First, find the user to get their DN
    const user = await findUser(username);
    if (!user) {
        throw new Error('User not found');
    }

    // Check if account is disabled (bit 2 of userAccountControl)
    const uac = parseInt(user.userAccountControl, 10);
    if (uac && (uac & 2) !== 0) {
        throw new Error('Account is disabled');
    }

    // Check if account is locked out
    if (user.lockoutTime && parseInt(user.lockoutTime, 10) > 0) {
        throw new Error('Account is locked out');
    }

    // Attempt bind with user's credentials
    const userClient = await bindClient(user.dn, password);
    userClient.unbind(() => {});

    return user;
}

/**
 * Change a user's password in AD.
 * Requires the service account to have "Reset Password" permission.
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
        // AD requires the password to be enclosed in quotes and UTF-16LE encoded
        const encodedPassword = Buffer.from(`"${newPassword}"`, 'utf16le');

        const change = new ldap.Change({
            operation: 'replace',
            modification: new ldap.Attribute({
                type: 'unicodePwd',
                values: [encodedPassword],
            }),
        });

        // Must await: the finally block would otherwise close the connection before AD replies
        return await new Promise((resolve, reject) => {
            client.modify(userDN, change, (err) => {
                if (err) {
                    // Parse common AD password policy errors
                    if (err.message && err.message.includes('0000052D')) {
                        reject(new Error('Password does not meet the domain password policy requirements'));
                    } else if (err.message && err.message.includes('00000056')) {
                        reject(new Error('Current password is incorrect'));
                    } else {
                        reject(new Error(`Failed to change password: ${err.message}`));
                    }
                } else {
                    resolve();
                }
            });
        });
    } finally {
        client.unbind(() => {});
    }
}

/**
 * Change password with old password verification (for authenticated change).
 * User must provide current password.
 * @param {string} userDN - User's DN
 * @param {string} oldPassword - Current password
 * @param {string} newPassword - New password
 * @returns {Promise<void>}
 */
async function changePasswordWithOld(userDN, oldPassword, newPassword) {
    // First verify the old password by binding as the user
    const userClient = await bindClient(userDN, oldPassword);
    userClient.unbind(() => {});

    // Then change the password using service account
    await changePassword(userDN, newPassword);
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

module.exports = config.ad.mock
    ? require('./mockLdapService')
    : {
        findUser,
        authenticateUser,
        changePassword,
        changePasswordWithOld,
        isAdmin,
        isServiceAccountPrivileged,
    };
