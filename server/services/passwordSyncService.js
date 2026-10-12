// Keeps the optional second domain (AD2_*) on the same password as the first.
// Two steps so nothing is written while the second domain is unreachable:
//   prepare(username)  before the first-domain write: finds the matching account (same sAMAccountName)
//   apply(plan, pw)    after the first-domain write succeeded
// The match is by name only, so accounts that a same-named first-domain user must never take over are
// refused: disabled, protected (adminCount=1, e.g. Domain Admins) and the AD2 bind account itself.
const config = require('../config/default');
const ldapService = require('./ldapService');
const { accountName } = require('./windowsDirectoryService');

const UAC_ACCOUNT_DISABLED = 2;

class SecondaryUnavailableError extends Error {
    constructor(domain, reason) {
        super(`${domain} unavailable: ${reason}`);
        this.domain = domain;
    }
}

function isEnabled() {
    return Boolean(ldapService.secondary);
}

// Reason the matched account must not be written, or null
function refusalReason(user) {
    if ((parseInt(user.userAccountControl, 10) & UAC_ACCOUNT_DISABLED) !== 0) return 'account is disabled';
    if (String(user.adminCount) === '1') return 'protected account (adminCount=1)';

    const bindDN = config.ad.secondary?.bindDN;
    if (bindDN) {
        const sameDn = String(user.dn).toLowerCase() === bindDN.toLowerCase();
        const sameName = String(user.sAMAccountName).toLowerCase() === accountName(bindDN).toLowerCase();
        if (sameDn || sameName) return 'account is the AD2 service account';
    }
    return null;
}

/**
 * @returns {Promise<{domain: string, dn: string|null, reason?: string}|null>} null when no second domain is configured
 * @throws {SecondaryUnavailableError} when the second domain cannot be searched
 */
async function prepare(username) {
    const secondary = ldapService.secondary;
    if (!secondary) return null;

    let user;
    try {
        user = await secondary.findUser(username);
    } catch (err) {
        throw new SecondaryUnavailableError(secondary.name, err.message);
    }
    if (!user) return { domain: secondary.name, dn: null };

    const reason = refusalReason(user);
    if (reason) return { domain: secondary.name, dn: null, reason };
    return { domain: secondary.name, dn: user.dn };
}

/**
 * @returns {Promise<{domain: string, status: 'synced'|'not_found'|'failed', error?: string, reason?: string}|null>}
 *   not_found also covers refused accounts (reason set), so the user sees no difference
 */
async function apply(plan, newPassword) {
    if (!plan) return null;
    if (!plan.dn) return { domain: plan.domain, status: 'not_found', reason: plan.reason };

    try {
        await ldapService.secondary.changePassword(plan.dn, newPassword);
        return { domain: plan.domain, status: 'synced' };
    } catch (err) {
        return { domain: plan.domain, status: 'failed', error: err.message };
    }
}

module.exports = { isEnabled, prepare, apply, refusalReason, SecondaryUnavailableError };
