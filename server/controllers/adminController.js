const db = require('../config/db');
const { MATCH_TYPES } = require('../services/passwordExceptionService');
const { logAudit, getOrCreateUser } = require('./authController');
const ldapService = require('../services/ldapService');
const settingsService = require('../services/settingsService');
const mailService = require('../services/mailService');
const notificationService = require('../services/notificationService');
const passwordReminderService = require('../services/passwordReminderService');

const UAC_ACCOUNT_DISABLED = 2;

/**
 * GET /api/admin/users
 * List all users with enrollment status.
 * Query params: page, limit, search, filter (all|enrolled|pending|locked|admins)
 */
async function getUsers(req, res) {
    try {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
        const offset = (page - 1) * limit;
        const search = req.query.search || '';
        const filter = req.query.filter || 'all';

        let whereClause = '';
        const params = [];

        if (search) {
            params.push(`%${search}%`);
            whereClause += ` WHERE (username ILIKE $${params.length} OR display_name ILIKE $${params.length} OR email ILIKE $${params.length})`;
        }

        if (filter !== 'all') {
            const connector = whereClause ? ' AND' : ' WHERE';
            switch (filter) {
                case 'enrolled':
                    whereClause += `${connector} is_enrolled = TRUE`;
                    break;
                case 'pending':
                    whereClause += `${connector} is_enrolled = FALSE`;
                    break;
                case 'locked':
                    whereClause += `${connector} locked = TRUE`;
                    break;
                case 'admins':
                    whereClause += `${connector} is_portal_admin = TRUE`;
                    break;
            }
        }

        const countResult = await db.query(`SELECT COUNT(*) FROM users${whereClause}`, params);
        const totalCount = parseInt(countResult.rows[0].count, 10);

        params.push(limit, offset);
        const result = await db.query(
            `SELECT id, username, display_name, email, is_enrolled, totp_enabled,
                    security_questions_set, locked, is_portal_admin, failed_attempts, created_at, updated_at
             FROM users${whereClause}
             ORDER BY created_at DESC
             LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );

        res.json({
            success: true,
            data: {
                users: result.rows,
                pagination: {
                    page,
                    limit,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                },
            },
        });
    } catch (err) {
        console.error('[Admin] Get users error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load users.',
        });
    }
}

/**
 * GET /api/admin/stats
 * Enrollment statistics.
 */
async function getStats(req, res) {
    try {
        const result = await db.query(`
            SELECT
                COUNT(*) AS total_users,
                COUNT(*) FILTER (WHERE is_enrolled = TRUE) AS enrolled_users,
                COUNT(*) FILTER (WHERE is_enrolled = FALSE) AS pending_users,
                COUNT(*) FILTER (WHERE locked = TRUE) AS locked_users,
                COUNT(*) FILTER (WHERE totp_enabled = TRUE) AS totp_enabled_users,
                COUNT(*) FILTER (WHERE security_questions_set = TRUE) AS sq_set_users
            FROM users
        `);

        const stats = result.rows[0];

        // Recent activity (last 7 days)
        const activityResult = await db.query(`
            SELECT action, COUNT(*) AS count
            FROM audit_log
            WHERE created_at > NOW() - INTERVAL '7 days'
            GROUP BY action
            ORDER BY count DESC
        `);

        res.json({
            success: true,
            data: {
                ...stats,
                recentActivity: activityResult.rows,
            },
        });
    } catch (err) {
        console.error('[Admin] Get stats error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load statistics.',
        });
    }
}

/**
 * GET /api/admin/audit-log
 * View audit log with filtering and pagination.
 * Query params: page, limit, username (partial match), action, startDate, endDate
 */
async function getAuditLog(req, res) {
    try {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
        const offset = (page - 1) * limit;

        const conditions = [];
        const params = [];

        // Partial, case-insensitive match so "sagar" also finds "sagar.s"
        if (req.query.username) {
            params.push(`%${req.query.username}%`);
            conditions.push(`username ILIKE $${params.length}`);
        }

        if (req.query.action) {
            params.push(req.query.action);
            conditions.push(`action = $${params.length}`);
        }

        if (req.query.startDate) {
            params.push(req.query.startDate);
            conditions.push(`created_at >= $${params.length}`);
        }

        if (req.query.endDate) {
            params.push(req.query.endDate);
            conditions.push(`created_at <= $${params.length}`);
        }

        const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';

        const countResult = await db.query(`SELECT COUNT(*) FROM audit_log${whereClause}`, params);
        const totalCount = parseInt(countResult.rows[0].count, 10);

        params.push(limit, offset);
        const result = await db.query(
            `SELECT id, username, action, method, ip_address, success, details, created_at
             FROM audit_log${whereClause}
             ORDER BY created_at DESC
             LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );

        res.json({
            success: true,
            data: {
                logs: result.rows,
                pagination: {
                    page,
                    limit,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                },
            },
        });
    } catch (err) {
        console.error('[Admin] Get audit log error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load audit log.',
        });
    }
}

/**
 * PUT /api/admin/users/:id/lock
 * Lock or unlock a user's portal access.
 * Body: { locked: true/false }
 */
async function toggleLock(req, res) {
    try {
        const userId = parseInt(req.params.id, 10);
        const { locked } = req.body;

        if (typeof locked !== 'boolean') {
            return res.status(400).json({
                success: false,
                message: 'The "locked" field must be true or false.',
            });
        }

        const result = await db.query(
            'UPDATE users SET locked = $1, token_version = token_version + CASE WHEN $1 THEN 1 ELSE 0 END, updated_at = NOW() WHERE id = $2 RETURNING username',
            [locked, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found.',
            });
        }

        const action = locked ? 'user_locked' : 'user_unlocked';
        await logAudit(req.user.userId, req.user.username, action, null, req, true,
            `${action} user: ${result.rows[0].username}`);

        res.json({
            success: true,
            message: `User ${locked ? 'locked' : 'unlocked'} successfully.`,
        });
    } catch (err) {
        console.error('[Admin] Toggle lock error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to update user lock status.',
        });
    }
}

/**
 * PUT /api/admin/users/:id/admin
 * Grant or revoke portal admin rights. Members of AD_ADMIN_GROUP stay admins regardless.
 * Body: { isAdmin: true/false }
 */
async function setPortalAdmin(req, res) {
    try {
        const userId = parseInt(req.params.id, 10);
        const { isAdmin } = req.body;

        if (typeof isAdmin !== 'boolean') {
            return res.status(400).json({
                success: false,
                message: 'The "isAdmin" field must be true or false.',
            });
        }

        if (!isAdmin && userId === req.user.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot remove your own admin rights. Ask another admin.',
            });
        }

        const result = await db.query(
            'UPDATE users SET is_portal_admin = $1, updated_at = NOW() WHERE id = $2 RETURNING username',
            [isAdmin, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found.',
            });
        }

        const action = isAdmin ? 'admin_granted' : 'admin_revoked';
        await logAudit(req.user.userId, req.user.username, action, null, req, true,
            `${action} for: ${result.rows[0].username}`);

        res.json({
            success: true,
            message: isAdmin
                ? `${result.rows[0].username} is now a portal admin.`
                : `Portal admin rights removed from ${result.rows[0].username}.`,
        });
    } catch (err) {
        console.error('[Admin] Set portal admin error:', err.message);
        res.status(500).json({
            success: false,
            message: 'Failed to update admin rights.',
        });
    }
}

/**
 * POST /api/admin/admins
 * Grant portal admin rights by AD username (the user does not need to have signed in yet).
 * Body: { username }
 */
async function addPortalAdmin(req, res) {
    try {
        const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
        if (!username || username.length > 100) {
            return res.status(400).json({
                success: false,
                message: 'Enter a username.',
            });
        }

        let adUser;
        try {
            adUser = await ldapService.findUser(username);
        } catch (err) {
            console.error('[Admin] Add admin lookup error:', err.message);
            return res.status(503).json({
                success: false,
                message: 'The directory service is currently unavailable. Please try again later.',
            });
        }

        if (!adUser) {
            return res.status(404).json({
                success: false,
                message: 'No user with this username was found in Active Directory.',
            });
        }
        if (parseInt(adUser.userAccountControl, 10) & UAC_ACCOUNT_DISABLED) {
            return res.status(400).json({
                success: false,
                message: 'This account is disabled in Active Directory.',
            });
        }

        const dbUser = await getOrCreateUser(adUser);
        if (dbUser.is_portal_admin) {
            return res.status(409).json({
                success: false,
                message: `${dbUser.username} is already a portal admin.`,
            });
        }

        await db.query('UPDATE users SET is_portal_admin = TRUE, updated_at = NOW() WHERE id = $1', [dbUser.id]);

        await logAudit(req.user.userId, req.user.username, 'admin_granted', null, req, true,
            `admin_granted for: ${dbUser.username}`);

        res.status(201).json({
            success: true,
            message: `${dbUser.username} is now a portal admin.`,
        });
    } catch (err) {
        console.error('[Admin] Add portal admin error:', err.message);
        res.status(500).json({
            success: false,
            message: 'Failed to add admin.',
        });
    }
}

/**
 * GET /api/admin/questions
 * List all security questions (including inactive).
 */
async function getQuestions(req, res) {
    try {
        const result = await db.query(
            'SELECT id, question_text, is_active, sort_order, created_at FROM security_questions ORDER BY sort_order ASC'
        );

        res.json({
            success: true,
            data: result.rows,
        });
    } catch (err) {
        console.error('[Admin] Get questions error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load questions.',
        });
    }
}

/**
 * POST /api/admin/questions
 * Add a new security question.
 * Body: { questionText, sortOrder? }
 */
async function addQuestion(req, res) {
    try {
        const { questionText, sortOrder } = req.body;

        if (!questionText || questionText.trim().length < 10) {
            return res.status(400).json({
                success: false,
                message: 'Question text must be at least 10 characters long.',
            });
        }

        const result = await db.query(
            'INSERT INTO security_questions (question_text, sort_order) VALUES ($1, $2) RETURNING *',
            [questionText.trim(), sortOrder || 0]
        );

        await logAudit(req.user.userId, req.user.username, 'question_added', null, req, true, questionText);

        res.status(201).json({
            success: true,
            data: result.rows[0],
            message: 'Question added successfully.',
        });
    } catch (err) {
        console.error('[Admin] Add question error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to add question.',
        });
    }
}

/**
 * PUT /api/admin/questions/:id
 * Update a security question (text, active status, sort order).
 * Body: { questionText?, isActive?, sortOrder? }
 */
async function updateQuestion(req, res) {
    try {
        const questionId = parseInt(req.params.id, 10);
        const { questionText, isActive, sortOrder } = req.body;

        const updates = [];
        const params = [];

        if (questionText !== undefined) {
            if (questionText.trim().length < 10) {
                return res.status(400).json({
                    success: false,
                    message: 'Question text must be at least 10 characters long.',
                });
            }
            params.push(questionText.trim());
            updates.push(`question_text = $${params.length}`);
        }

        if (isActive !== undefined) {
            params.push(isActive);
            updates.push(`is_active = $${params.length}`);
        }

        if (sortOrder !== undefined) {
            params.push(sortOrder);
            updates.push(`sort_order = $${params.length}`);
        }

        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No updates provided.',
            });
        }

        params.push(questionId);
        const result = await db.query(
            `UPDATE security_questions SET ${updates.join(', ')} WHERE id = $${params.length} RETURNING *`,
            params
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Question not found.',
            });
        }

        await logAudit(req.user.userId, req.user.username, 'question_updated', null, req, true,
            `Updated question #${questionId}`);

        res.json({
            success: true,
            data: result.rows[0],
            message: 'Question updated successfully.',
        });
    } catch (err) {
        console.error('[Admin] Update question error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to update question.',
        });
    }
}

/**
 * PUT /api/admin/users/:id/reset-enrollment
 * Reset a user's enrollment (clear security questions and TOTP).
 */
async function resetEnrollment(req, res) {
    const client = await db.getClient();
    try {
        const userId = parseInt(req.params.id, 10);

        await client.query('BEGIN');

        // Delete security answers
        await client.query('DELETE FROM user_security_answers WHERE user_id = $1', [userId]);

        // Reset enrollment flags
        const result = await client.query(
            `UPDATE users SET
                is_enrolled = FALSE,
                totp_secret = NULL,
                totp_pending_secret = NULL,
                totp_enabled = FALSE,
                totp_last_used_step = NULL,
                security_questions_set = FALSE,
                failed_attempts = 0,
                last_failed_attempt = NULL,
                updated_at = NOW()
             WHERE id = $1 RETURNING username`,
            [userId]
        );

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'User not found.',
            });
        }

        await client.query('COMMIT');

        await logAudit(req.user.userId, req.user.username, 'enrollment_reset', null, req, true,
            `Reset enrollment for: ${result.rows[0].username}`);

        res.json({
            success: true,
            message: 'User enrollment has been reset. They will need to enroll again on next login.',
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[Admin] Reset enrollment error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to reset enrollment.',
        });
    } finally {
        client.release();
    }
}

/**
 * GET /api/admin/password-exceptions
 * List all words/phrases that are not allowed in new passwords.
 */
async function getPasswordExceptions(req, res) {
    try {
        const result = await db.query(
            `SELECT id, term, match_type, is_active, created_by, created_at, updated_at
             FROM password_exceptions ORDER BY LOWER(term) ASC`
        );
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error('[Admin] Get password exceptions error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to load password exceptions.' });
    }
}

function validateException({ term, matchType }, partial) {
    if (term !== undefined || !partial) {
        if (typeof term !== 'string' || term.trim().length < 3 || term.trim().length > 128) {
            return 'The word or phrase must be 3 to 128 characters long.';
        }
    }
    if (matchType !== undefined && !MATCH_TYPES.includes(matchType)) {
        return 'Match type must be "contains" or "exact".';
    }
    return null;
}

/**
 * POST /api/admin/password-exceptions
 * Body: { term, matchType?: 'contains' | 'exact' }
 */
async function addPasswordException(req, res) {
    try {
        const error = validateException(req.body, false);
        if (error) return res.status(400).json({ success: false, message: error });

        const term = req.body.term.trim();
        const result = await db.query(
            `INSERT INTO password_exceptions (term, match_type, created_by) VALUES ($1, $2, $3)
             RETURNING id, term, match_type, is_active, created_by, created_at, updated_at`,
            [term, req.body.matchType || 'contains', req.user.username]
        );

        await logAudit(req.user.userId, req.user.username, 'password_exception_added', null, req, true, term);

        res.status(201).json({ success: true, data: result.rows[0], message: 'Password exception added.' });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ success: false, message: 'This word or phrase is already in the list.' });
        }
        console.error('[Admin] Add password exception error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to add password exception.' });
    }
}

/**
 * PUT /api/admin/password-exceptions/:id
 * Body: { term?, matchType?, isActive? }
 */
async function updatePasswordException(req, res) {
    try {
        const id = parseInt(req.params.id, 10);
        const { term, matchType, isActive } = req.body;

        const error = validateException(req.body, true);
        if (error) return res.status(400).json({ success: false, message: error });
        if (isActive !== undefined && typeof isActive !== 'boolean') {
            return res.status(400).json({ success: false, message: 'The "isActive" field must be true or false.' });
        }

        const updates = [];
        const params = [];
        if (term !== undefined) {
            params.push(term.trim());
            updates.push(`term = $${params.length}`);
        }
        if (matchType !== undefined) {
            params.push(matchType);
            updates.push(`match_type = $${params.length}`);
        }
        if (isActive !== undefined) {
            params.push(isActive);
            updates.push(`is_active = $${params.length}`);
        }
        if (updates.length === 0) {
            return res.status(400).json({ success: false, message: 'No updates provided.' });
        }

        params.push(id);
        const result = await db.query(
            `UPDATE password_exceptions SET ${updates.join(', ')}, updated_at = NOW() WHERE id = $${params.length}
             RETURNING id, term, match_type, is_active, created_by, created_at, updated_at`,
            params
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Password exception not found.' });
        }

        await logAudit(req.user.userId, req.user.username, 'password_exception_updated', null, req, true,
            `Updated password exception #${id}: ${result.rows[0].term}`);

        res.json({ success: true, data: result.rows[0], message: 'Password exception updated.' });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ success: false, message: 'This word or phrase is already in the list.' });
        }
        console.error('[Admin] Update password exception error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to update password exception.' });
    }
}

/**
 * DELETE /api/admin/password-exceptions/:id
 */
async function deletePasswordException(req, res) {
    try {
        const id = parseInt(req.params.id, 10);
        const result = await db.query('DELETE FROM password_exceptions WHERE id = $1 RETURNING term', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Password exception not found.' });
        }

        await logAudit(req.user.userId, req.user.username, 'password_exception_deleted', null, req, true, result.rows[0].term);

        res.json({ success: true, message: 'Password exception removed.' });
    } catch (err) {
        console.error('[Admin] Delete password exception error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to remove password exception.' });
    }
}

// ---- Mail and expiry reminders (Administration -> Mail & Reminders) ----

/**
 * GET /api/admin/settings
 * Effective mail and reminder settings, with the .env fallbacks. The SMTP password is never returned.
 */
async function getSettings(req, res) {
    try {
        res.json({ success: true, data: await settingsService.describe() });
    } catch (err) {
        console.error('[Admin] Get settings error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to load settings.' });
    }
}

/**
 * PUT /api/admin/settings
 * Body: { settings: { 'mail.host': '...', 'reminders.days': '14,7,1', ... } }
 * Only the keys sent are changed; an empty SMTP field falls back to .env, and the unchanged password
 * placeholder keeps the stored secret.
 */
async function updateSettings(req, res) {
    try {
        const values = req.body?.settings;
        if (!values || typeof values !== 'object' || Array.isArray(values)) {
            return res.status(400).json({ success: false, message: 'No settings were supplied.' });
        }

        const changed = await settingsService.save(values, req.user.username);
        if (changed.length) {
            await logAudit(req.user.userId, req.user.username, 'settings_updated', null, req, true, changed.join(', '));
        }

        res.json({
            success: true,
            data: await settingsService.describe(),
            message: changed.length ? 'Settings saved.' : 'No changes to save.',
        });
    } catch (err) {
        if (err.validation) return res.status(400).json({ success: false, message: err.message });
        console.error('[Admin] Update settings error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to save settings.' });
    }
}

/**
 * POST /api/admin/settings/test-mail
 * Body: { to }  Sends one test message through the current settings.
 */
async function sendTestMail(req, res) {
    const to = typeof req.body?.to === 'string' ? req.body.to.trim() : '';
    try {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to) || to.length > 255) {
            return res.status(400).json({ success: false, message: 'Enter a valid recipient address.' });
        }
        if (!mailService.isEnabled()) {
            return res.status(400).json({ success: false, message: 'Set an SMTP host before sending a test mail.' });
        }

        const { host, port, from } = settingsService.current().mail;
        await mailService.send({
            to,
            subject: `${settingsService.current().mail.portalName}: test message`,
            text: notificationService.testMessage({ host, port, from, requestedBy: req.user.username }),
        });
        await logAudit(req.user.userId, req.user.username, 'mail_test', null, req, true, `Test mail sent to ${to}`);

        res.json({ success: true, message: `Test mail sent to ${to}.` });
    } catch (err) {
        await logAudit(req.user.userId, req.user.username, 'mail_test', null, req, false, err.message);
        res.status(502).json({ success: false, message: `The relay refused the test mail: ${err.message}` });
    }
}

/**
 * POST /api/admin/reminders/run
 * Body: { send?: boolean }  Runs the expiry reminder pass now: a preview by default, or a real send.
 * The same per-stage records are used, so a manual send never duplicates a reminder already mailed.
 */
async function runReminders(req, res) {
    const send = req.body?.send === true;
    try {
        if (send && !mailService.isEnabled()) {
            return res.status(400).json({ success: false, message: 'Set an SMTP host before sending reminders.' });
        }

        const result = await passwordReminderService.runOnce({ dryRun: !send });
        const summary = `${result.checked} checked, ${result.due.length} due`
            + (send ? `, ${result.sent} sent, ${result.failed} failed` : ' (preview, nothing sent)');
        await logAudit(req.user.userId, req.user.username, 'reminder_run', null, req, true, summary);

        res.json({
            success: true,
            data: {
                send,
                checked: result.checked,
                expiring: result.expiring,
                skipped: result.skipped,
                sent: result.sent,
                failed: result.failed,
                // Capped: a preview of a large domain can list thousands of accounts
                due: result.due.slice(0, 200).map((d) => ({
                    username: d.username, mail: d.mail, daysLeft: d.daysLeft, expiresAt: d.expiresAt,
                })),
                dueTotal: result.due.length,
            },
            message: summary,
        });
    } catch (err) {
        console.error('[Admin] Reminder run error:', err.message);
        await logAudit(req.user.userId, req.user.username, 'reminder_run', null, req, false, err.message);
        res.status(502).json({ success: false, message: `The reminder run failed: ${err.message}` });
    }
}

module.exports = {
    getUsers,
    getStats,
    getAuditLog,
    toggleLock,
    setPortalAdmin,
    addPortalAdmin,
    getQuestions,
    addQuestion,
    updateQuestion,
    resetEnrollment,
    getPasswordExceptions,
    addPasswordException,
    updatePasswordException,
    deletePasswordException,
    getSettings,
    updateSettings,
    sendTestMail,
    runReminders,
};
