const jwt = require('jsonwebtoken');
const config = require('../config/default');

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

module.exports = { authenticate, optionalAuth };
