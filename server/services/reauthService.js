// "Confirm your Windows password" for sensitive actions by a user who is already signed in.
const ldapService = require('./ldapService');

/**
 * @param {string} username - sAMAccountName of the signed-in user
 * @param {string} password - what the user typed
 * @returns {Promise<'ok'|'missing'|'wrong'|'unavailable'>}
 */
async function verifyPassword(username, password) {
    if (typeof password !== 'string' || password.length === 0) return 'missing';
    try {
        // The caller is signed in already, so the account state may be shown
        await ldapService.authenticateUser(username, password, { revealState: true });
        return 'ok';
    } catch (err) {
        return /unreachable|connection error/i.test(err.message) ? 'unavailable' : 'wrong';
    }
}

module.exports = { verifyPassword };
