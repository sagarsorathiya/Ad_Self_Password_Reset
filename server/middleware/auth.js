const jwt = require('jsonwebtoken');
const config = require('../config/default');
const db = require('../config/db');

/**
 * JWT authentication middleware.
 * Expects: Authorization: Bearer <token>
 * Sets req.user with decoded token payload.
 */
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No token provided.',
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });
        // Refresh and reset tokens share the signing key and must never act as a session
        if (decoded.type !== 'access') {
            return res.status(401).json({ success: false, message: 'Invalid token.' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token has expired. Please log in again.',
                code: 'TOKEN_EXPIRED',
            });
        }
        return res.status(401).json({
            success: false,
            message: 'Invalid token.',
        });
    }
}

/**
 * Optional authentication middleware.
 * If a valid token is present, sets req.user. Otherwise, continues without it.
 */
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return next();
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });
        if (decoded.type === 'access') req.user = decoded;
    } catch {
        // Token invalid or expired — continue without user
    }

    next();
}

/**
 * After authenticate: the session must still be current. A logout elsewhere, an admin lock or a password
 * change bumps users.token_version, which ends every access token at once instead of when it expires.
 */
async function requireActiveSession(req, res, next) {
    // Tokens issued before tv existed: the client refreshes once (TOKEN_EXPIRED) and gets one
    if (req.user.tv === undefined) {
        return res.status(401).json({ success: false, code: 'TOKEN_EXPIRED', message: 'Please sign in again.' });
    }
    try {
        const { rows } = await db.query('SELECT token_version, locked FROM users WHERE id = $1', [req.user.userId]);
        if (rows.length === 0 || rows[0].locked || rows[0].token_version !== req.user.tv) {
            return res.status(401).json({
                success: false,
                code: 'SESSION_REVOKED',
                message: 'Your session has ended. Please sign in again.',
            });
        }
        return next();
    } catch (err) {
        console.error('[Auth] Session check failed:', err.message);
        return res.status(500).json({ success: false, message: 'An error occurred. Please try again.' });
    }
}

module.exports = { authenticate, optionalAuth, requireActiveSession };
