// Portal sessions: every refresh token carries tv = users.token_version, every access token too.
// Bumping the version ends all of a user's sessions (requireActiveSession checks access tokens per request).
const db = require('../config/db');

/** Ends every session of the user: refresh tokens and, through requireActiveSession, access tokens. */
async function revokeAll(userId) {
    await db.query('UPDATE users SET token_version = token_version + 1, updated_at = NOW() WHERE id = $1', [userId]);
}

module.exports = { revokeAll };
