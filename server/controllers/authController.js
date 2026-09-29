const jwt = require('jsonwebtoken');
const config = require('../config/default');
const ldapService = require('../services/ldapService');
const db = require('../config/db');

/**
 * POST /api/auth/login
 * Authenticate user against Active Directory.
 */
async function login(req, res) {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required.',
            });
        }

        // Authenticate against AD
        const adUser = await ldapService.authenticateUser(username, password);

        // Check/create user record in our database
        let dbUser = await getOrCreateUser(adUser);

        // Check if user is locked in our portal
        if (dbUser.locked) {
            await logAudit(null, username, 'login', null, req, false, 'Account locked in portal');
            return res.status(403).json({
                success: false,
                message: 'Your account has been locked. Please contact your administrator.',
            });
        }

        // Reset failed attempts on successful login
        if (dbUser.failed_attempts > 0) {
            await db.query(
                'UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL, updated_at = NOW() WHERE id = $1',
                [dbUser.id]
            );
        }

        // Check admin status
        const isAdmin = ldapService.isAdmin(adUser);

        // Generate JWT
        const token = jwt.sign(
            {
                type: 'access',
                userId: dbUser.id,
                username: adUser.sAMAccountName,
                displayName: adUser.displayName || adUser.sAMAccountName,
                email: adUser.mail || '',
                dn: adUser.dn,
                isAdmin,
                isEnrolled: dbUser.is_enrolled,
            },
            config.jwt.secret,
            { expiresIn: config.jwt.expiry }
        );

        // Generate refresh token
        const refreshToken = jwt.sign(
            {
                userId: dbUser.id,
                username: adUser.sAMAccountName,
                type: 'refresh',
                tv: dbUser.token_version,
            },
            config.jwt.secret,
            { expiresIn: config.jwt.refreshExpiry }
        );

        // Log successful login
        await logAudit(dbUser.id, username, 'login', null, req, true);

        res.json({
            success: true,
            data: {
                token,
                refreshToken,
                user: {
                    id: dbUser.id,
                    username: adUser.sAMAccountName,
                    displayName: adUser.displayName || adUser.sAMAccountName,
                    email: adUser.mail || '',
                    isAdmin,
                    isEnrolled: dbUser.is_enrolled,
                    totpEnabled: dbUser.totp_enabled,
                    securityQuestionsSet: dbUser.security_questions_set,
                },
            },
        });
    } catch (err) {
        // Log failed login
        // Unknown "usernames" are frequently passwords typed into the wrong field; never persist them
        const auditName = err.message === 'User not found' || typeof req.body?.username !== 'string'
            ? '(unknown user)'
            : req.body.username;
        await logAudit(null, auditName, 'login', null, req, false, err.message);

        if (err.message === 'Invalid credentials' || err.message === 'User not found') {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password.',
            });
        }

        if (err.message === 'Account is disabled') {
            return res.status(403).json({
                success: false,
                message: 'Your account is disabled. Please contact your administrator.',
            });
        }

        if (err.message === 'Account is locked out') {
            return res.status(403).json({
                success: false,
                message: 'Your account is locked out. Please wait and try again, or contact your administrator.',
            });
        }

        console.error('[Auth] Login error:', err);

        if (err.message.startsWith('Directory server unreachable') || err.message.startsWith('LDAP connection error')) {
            return res.status(503).json({
                success: false,
                message: 'The directory service is currently unavailable. Please try again later or contact IT support.',
            });
        }

        res.status(500).json({
            success: false,
            message: 'An error occurred during authentication. Please try again.',
        });
    }
}

/**
 * POST /api/auth/refresh
 * Refresh an expired access token using a refresh token.
 */
async function refresh(req, res) {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({
                success: false,
                message: 'Refresh token is required.',
            });
        }

        const decoded = jwt.verify(refreshToken, config.jwt.secret, { algorithms: ['HS256'] });

        if (decoded.type !== 'refresh') {
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token.',
            });
        }

        // Get current user data
        const result = await db.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'User not found.',
            });
        }

        const dbUser = result.rows[0];

        if (dbUser.locked || decoded.tv !== dbUser.token_version) {
            return res.status(401).json({
                success: false,
                message: 'Session has been revoked. Please log in again.',
                code: 'REFRESH_REVOKED',
            });
        }
        let adUser;
        let isAdmin = false;
        try {
            adUser = await ldapService.findUser(dbUser.username);
            if (adUser) {
                isAdmin = ldapService.isAdmin(adUser);
            }
        } catch {
            // If AD is unreachable, still issue token with cached info
        }

        const token = jwt.sign(
            {
                type: 'access',
                userId: dbUser.id,
                username: dbUser.username,
                displayName: adUser?.displayName || dbUser.display_name || dbUser.username,
                email: adUser?.mail || dbUser.email || '',
                dn: adUser?.dn || '',
                isAdmin,
                isEnrolled: dbUser.is_enrolled,
            },
            config.jwt.secret,
            { expiresIn: config.jwt.expiry }
        );

        res.json({
            success: true,
            data: { token },
        });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Refresh token has expired. Please log in again.',
                code: 'REFRESH_EXPIRED',
            });
        }
        res.status(401).json({
            success: false,
            message: 'Invalid refresh token.',
        });
    }
}

/**
 * GET /api/auth/me
 * Get current user info and enrollment status.
 */
async function me(req, res) {
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found.',
            });
        }

        const dbUser = result.rows[0];

        res.json({
            success: true,
            data: {
                id: dbUser.id,
                username: dbUser.username,
                displayName: dbUser.display_name || req.user.displayName,
                email: dbUser.email || req.user.email,
                isAdmin: req.user.isAdmin,
                isEnrolled: dbUser.is_enrolled,
                totpEnabled: dbUser.totp_enabled,
                securityQuestionsSet: dbUser.security_questions_set,
            },
        });
    } catch (err) {
        console.error('[Auth] Me error:', err);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/auth/logout
 * Client-side logout (invalidate token on client).
 */
async function logout(req, res) {
    try {
        await db.query('UPDATE users SET token_version = token_version + 1 WHERE id = $1', [req.user.userId]);
    } catch (err) {
        console.error('[Auth] Logout revoke error:', err);
    }
    await logAudit(req.user?.userId, req.user?.username, 'logout', null, req, true);
    res.json({ success: true, message: 'Logged out successfully.' });
}

// ---- Helper functions ----

/**
 * Get or create a user record in our database from AD user data.
 */
async function getOrCreateUser(adUser) {
    const username = adUser.sAMAccountName;

    let result = await db.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length > 0) {
        // Update display_name and email from AD
        await db.query(
            'UPDATE users SET display_name = $1, email = $2, updated_at = NOW() WHERE username = $3',
            [adUser.displayName || username, adUser.mail || '', username]
        );
        result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        return result.rows[0];
    }

    // Create new user record
    const insertResult = await db.query(
        'INSERT INTO users (username, display_name, email) VALUES ($1, $2, $3) RETURNING *',
        [username, adUser.displayName || username, adUser.mail || '']
    );

    return insertResult.rows[0];
}

/**
 * Log an audit event.
 */
async function logAudit(userId, username, action, method, req, success, details = null) {
    try {
        await db.query(
            `INSERT INTO audit_log (user_id, username, action, method, ip_address, user_agent, success, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [
                userId,
                username || 'unknown',
                action,
                method,
                req.ip || req.connection?.remoteAddress,
                req.headers?.['user-agent'] || '',
                success,
                details,
            ]
        );
    } catch (err) {
        console.error('[Audit] Failed to log event:', err);
    }
}

module.exports = { login, refresh, me, logout, logAudit };
