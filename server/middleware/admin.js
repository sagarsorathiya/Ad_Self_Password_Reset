const db = require('../config/db');

/**
 * Whether the access token's user was in AD_ADMIN_GROUP at sign-in.
 * Tokens issued before the adGroupAdmin claim existed only carry isAdmin.
 */
function isAdGroupAdmin(user) {
    return user.adGroupAdmin !== undefined ? user.adGroupAdmin === true : user.isAdmin === true;
}

/**
 * Admin role check middleware.
 * Must be used AFTER the authenticate middleware.
 * Admins are members of AD_ADMIN_GROUP (JWT claim) or users granted admin in the portal.
 * The portal grant is read from the database on every request, so granting and revoking take effect immediately.
 */
async function requireAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required.',
        });
    }

    if (isAdGroupAdmin(req.user)) return next();

    try {
        const result = await db.query(
            'SELECT 1 FROM users WHERE id = $1 AND is_portal_admin = TRUE AND locked = FALSE',
            [req.user.userId]
        );
        if (result.rows.length > 0) return next();
    } catch (err) {
        console.error('[Admin] Portal admin check failed:', err.message);
        return res.status(500).json({ success: false, message: 'An error occurred. Please try again.' });
    }

    return res.status(403).json({
        success: false,
        message: 'Access denied. Admin privileges required.',
    });
}

module.exports = { requireAdmin, isAdGroupAdmin };
