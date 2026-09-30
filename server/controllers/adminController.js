const db = require('../config/db');
const { MATCH_TYPES } = require('../services/passwordExceptionService');
const { logAudit } = require('./authController');

/**
 * GET /api/admin/users
 * List all users with enrollment status.
 * Query params: page, limit, search, filter (all|enrolled|pending|locked)
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
            }
        }

        const countResult = await db.query(`SELECT COUNT(*) FROM users${whereClause}`, params);
        const totalCount = parseInt(countResult.rows[0].count, 10);

        params.push(limit, offset);
        const result = await db.query(
            `SELECT id, username, display_name, email, is_enrolled, totp_enabled,
                    security_questions_set, locked, failed_attempts, created_at, updated_at
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
 * Query params: page, limit, username, action, startDate, endDate
 */
async function getAuditLog(req, res) {
    try {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
        const offset = (page - 1) * limit;

        const conditions = [];
        const params = [];

        if (req.query.username) {
            params.push(req.query.username);
            conditions.push(`username = $${params.length}`);
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

module.exports = {
    getUsers,
    getStats,
    getAuditLog,
    toggleLock,
    getQuestions,
    addQuestion,
    updateQuestion,
    resetEnrollment,
    getPasswordExceptions,
    addPasswordException,
    updatePasswordException,
    deletePasswordException,
};
