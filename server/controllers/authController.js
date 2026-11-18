const jwt = require('jsonwebtoken');
const config = require('../config/default');
const ldapService = require('../services/ldapService');
const settingsService = require('../services/settingsService');
const sessionService = require('../services/sessionService');
const reauthService = require('../services/reauthService');
const db = require('../config/db');
const { isAdGroupAdmin } = require('../middleware/admin');

const UAC_ACCOUNT_DISABLED = 2;

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

/**
 * Access token. tv = users.token_version (requireActiveSession), authTime = when the password was last proved
 * (first enrolment needs it recent).
 */
function signAccessToken(dbUser, adUser, { adGroupAdmin, isAdmin, authTime }) {
    return jwt.sign(
        {
            type: 'access',
            userId: dbUser.id,
            username: dbUser.username,
            displayName: adUser?.displayName || dbUser.display_name || dbUser.username,
            email: adUser?.mail || dbUser.email || '',
            isAdmin,
            adGroupAdmin,
            isEnrolled: dbUser.is_enrolled,
            tv: dbUser.token_version,
            authTime,
        },
        config.jwt.secret,
        { expiresIn: config.jwt.expiry }
    );
}

/**
 * POST /api/auth/login
 * Authenticate user against Active Directory.
 */
async function login(req, res) {
    try {
        const { username, password } = req.body;

        if (typeof username !== 'string' || !username || typeof password !== 'string' || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required.',
            });
        }

        // Authenticate against AD; with hideAccountState every failure reads as a wrong password
        const revealState = !settingsService.current().security.hideAccountState;
        const adUser = await ldapService.authenticateUser(username, password, { revealState });

        // Check/create user record in our database
        const dbUser = await getOrCreateUser(adUser);

        // Check if user is locked in our portal
        if (dbUser.locked) {
            await logAudit(dbUser.id, dbUser.username, 'login', null, req, false, 'Account locked in portal');
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

        // Admin = member of AD_ADMIN_GROUP or granted in the portal
        const adGroupAdmin = ldapService.isAdmin(adUser);
        const isAdmin = adGroupAdmin || dbUser.is_portal_admin;
        const authTime = nowSeconds();

        const token = signAccessToken(dbUser, adUser, { adGroupAdmin, isAdmin, authTime });

        // Refresh token: tv revokes it, at carries the sign-in time into refreshed access tokens
        const refreshToken = jwt.sign(
            {
                userId: dbUser.id,
                username: dbUser.username,
                type: 'refresh',
                tv: dbUser.token_version,
                at: authTime,
            },
            config.jwt.secret,
            { expiresIn: config.jwt.refreshExpiry }
        );

        // Log successful login
        await logAudit(dbUser.id, dbUser.username, 'login', null, req, true);

        res.json({
            success: true,
            data: {
                token,
                refreshToken,
                user: {
                    id: dbUser.id,
                    username: dbUser.username,
                    displayName: adUser.displayName || dbUser.username,
                    email: adUser.mail || '',
                    isAdmin,
                    isEnrolled: dbUser.is_enrolled,
                    totpEnabled: dbUser.totp_enabled,
                    smsEnabled: dbUser.sms_enabled,
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

        if (err.message === 'Password expired') {
            return res.status(403).json({
                success: false,
                code: 'PASSWORD_EXPIRED',
                message: 'Your password has expired or must be changed. Use Forgot password to set a new one.',
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

        console.error('[Auth] Login error:', err.message);

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

        let adUser = null;
        let directoryReachable = true;
        try {
            adUser = await ldapService.findUser(dbUser.username);
        } catch {
            // Availability: keep the session while AD is down, but admin rights are not re-confirmed
            directoryReachable = false;
        }
        if (directoryReachable) {
            const disabled = adUser && (parseInt(adUser.userAccountControl, 10) & UAC_ACCOUNT_DISABLED) !== 0;
            if (!adUser || disabled) {
                await sessionService.revokeAll(dbUser.id);
                await logAudit(dbUser.id, dbUser.username, 'session_revoked', null, req, true,
                    disabled ? 'Account disabled in AD' : 'Account no longer found in AD');
                return res.status(401).json({
                    success: false,
                    message: 'Session has been revoked. Please log in again.',
                    code: 'REFRESH_REVOKED',
                });
            }
        }
        const adGroupAdmin = adUser ? ldapService.isAdmin(adUser) : false;
        const isAdmin = adGroupAdmin || dbUser.is_portal_admin;

        // Refresh tokens from before `at` existed count as an old sign-in
        const token = signAccessToken(dbUser, adUser, { adGroupAdmin, isAdmin, authTime: decoded.at || 0 });

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
 * POST /api/auth/reauth
 * Body: { password }  Confirms the Windows password again and returns an access token with a fresh sign-in time.
 */
async function reauth(req, res) {
    try {
        const check = await reauthService.verifyPassword(req.user.username, req.body?.password);
        if (check !== 'ok') {
            if (check !== 'missing') await logAudit(req.user.userId, req.user.username, 'reauth', 'session', req, false, check);
            if (check === 'unavailable') {
                return res.status(503).json({ success: false, message: 'The directory service is currently unavailable.' });
            }
            return res.status(401).json({
                success: false,
                code: check === 'missing' ? 'REAUTH_REQUIRED' : 'REAUTH_FAILED',
                message: check === 'missing' ? 'Enter your Windows password.' : 'Current password is incorrect.',
            });
        }

        const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
        const dbUser = result.rows[0];
        const token = signAccessToken(dbUser, null, {
            adGroupAdmin: isAdGroupAdmin(req.user),
            isAdmin: req.user.isAdmin,
            authTime: nowSeconds(),
        });
        await logAudit(req.user.userId, req.user.username, 'reauth', 'session', req, true);
        res.json({ success: true, data: { token } });
    } catch (err) {
        console.error('[Auth] Reauth error:', err.message);
        res.status(500).json({ success: false, message: 'An error occurred. Please try again.' });
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
                isAdmin: isAdGroupAdmin(req.user) || (dbUser.is_portal_admin && !dbUser.locked),
                isEnrolled: dbUser.is_enrolled,
                totpEnabled: dbUser.totp_enabled,
                smsEnabled: dbUser.sms_enabled,
                securityQuestionsSet: dbUser.security_questions_set,
            },
        });
    } catch (err) {
        console.error('[Auth] Me error:', err.message);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/auth/logout
 * Ends the user's sessions on every device (token_version is per user).
 */
async function logout(req, res) {
    try {
        await sessionService.revokeAll(req.user.userId);
    } catch (err) {
        console.error('[Auth] Logout revoke error:', err.message);
    }
    await logAudit(req.user?.userId, req.user?.username, 'logout', null, req, true);
    res.json({ success: true, message: 'Logged out successfully.' });
}

// ---- Helper functions ----

/**
 * Get or create a user record in our database from AD user data.
 * Matched without regard to letter case (AD names are case-insensitive); the stored name follows AD's spelling.
 */
async function getOrCreateUser(adUser) {
    const username = adUser.sAMAccountName;
    const displayName = adUser.displayName || username;
    const email = adUser.mail || '';

    const found = await db.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (found.rows.length > 0) {
        const updated = await db.query(
            `UPDATE users SET username = $1, display_name = $2, email = $3, updated_at = NOW()
             WHERE id = $4 RETURNING *`,
            [username, displayName, email, found.rows[0].id]
        );
        return updated.rows[0];
    }

    // Two first logins at once: the second insert finds the row the first one created
    const inserted = await db.query(
        `INSERT INTO users (username, display_name, email) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING RETURNING *`,
        [username, displayName, email]
    );
    if (inserted.rows.length > 0) return inserted.rows[0];
    const existing = await db.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    return existing.rows[0];
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
        console.error('[Audit] Failed to log event:', err.message);
    }
}

module.exports = { login, refresh, reauth, me, logout, logAudit, getOrCreateUser };
