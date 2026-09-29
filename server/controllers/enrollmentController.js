const bcrypt = require('bcryptjs');
const db = require('../config/db');
const totpService = require('../services/totpService');
const ldapService = require('../services/ldapService');
const { logAudit } = require('./authController');

const BCRYPT_ROUNDS = 12;

// Replacing an existing factor must prove password knowledge, so a stolen session can't swap in attacker-controlled factors.
async function confirmCurrentPassword(req, res, method) {
    const { currentPassword } = req.body || {};
    if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
        res.status(401).json({
            success: false,
            code: 'REAUTH_REQUIRED',
            message: 'Please confirm your current password to change existing recovery settings.',
        });
        return false;
    }
    try {
        await ldapService.authenticateUser(req.user.username, currentPassword);
        return true;
    } catch (err) {
        await logAudit(req.user.userId, req.user.username, 'reauth', method, req, false, err.message);
        const unavailable = /unreachable|connection error/i.test(err.message);
        res.status(unavailable ? 503 : 401).json({
            success: false,
            code: 'REAUTH_FAILED',
            message: unavailable ? 'The directory service is currently unavailable.' : 'Current password is incorrect.',
        });
        return false;
    }
}

/**
 * GET /api/enrollment/questions
 * Get list of active security questions.
 */
async function getQuestions(req, res) {
    try {
        const result = await db.query(
            'SELECT id, question_text FROM security_questions WHERE is_active = TRUE ORDER BY sort_order ASC'
        );

        res.json({
            success: true,
            data: result.rows,
        });
    } catch (err) {
        console.error('[Enrollment] Get questions error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load security questions.',
        });
    }
}

/**
 * GET /api/enrollment/security-questions
 * The user's currently selected questions (answers are hashed and never returned).
 */
async function getMyQuestions(req, res) {
    try {
        const result = await db.query(
            `SELECT sq.id AS "questionId", sq.question_text AS "questionText"
             FROM user_security_answers usa
             JOIN security_questions sq ON sq.id = usa.question_id
             WHERE usa.user_id = $1
             ORDER BY usa.id ASC`,
            [req.user.userId]
        );
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error('[Enrollment] Get my questions error:', err);
        res.status(500).json({ success: false, message: 'Failed to load your security questions.' });
    }
}

/**
 * POST /api/enrollment/security-questions
 * Submit 3 selected security questions with answers.
 * Body: { answers: [{ questionId: 1, answer: "..." }, ...] }
 */
async function submitSecurityQuestions(req, res) {
    const client = await db.getClient();

    try {
        const { answers } = req.body;

        if (!answers || !Array.isArray(answers) || answers.length !== 3) {
            return res.status(400).json({
                success: false,
                message: 'Exactly 3 security questions with answers are required.',
            });
        }

        // Validate all questions exist and answers are non-empty
        const questionIds = answers.map(a => a.questionId);
        const uniqueIds = new Set(questionIds);
        if (uniqueIds.size !== 3) {
            return res.status(400).json({
                success: false,
                message: 'Please select 3 different questions.',
            });
        }

        for (const answer of answers) {
            if (answer.answer !== undefined && typeof answer.answer !== 'string') {
                return res.status(400).json({ success: false, message: 'Invalid answer format.' });
            }
        }

        // Blank answers keep the stored hash, but only for questions the user already has
        const existing = await db.query(
            'SELECT question_id, answer_hash FROM user_security_answers WHERE user_id = $1',
            [req.user.userId]
        );
        const existingHashes = new Map(existing.rows.map((r) => [r.question_id, r.answer_hash]));

        if (existingHashes.size > 0 && !(await confirmCurrentPassword(req, res, 'security_questions'))) return;

        for (const answer of answers) {
            const text = (answer.answer || '').trim();
            if (text.length === 0 && existingHashes.has(Number(answer.questionId))) continue;
            if (text.length < 2) {
                return res.status(400).json({
                    success: false,
                    message: 'All answers must be at least 2 characters long.',
                });
            }
        }

        // Verify questions exist in DB
        const questionCheck = await db.query(
            'SELECT id FROM security_questions WHERE id = ANY($1) AND (is_active = TRUE OR id = ANY($2))',
            [questionIds, [...existingHashes.keys()]]
        );

        if (questionCheck.rows.length !== 3) {
            return res.status(400).json({
                success: false,
                message: 'One or more selected questions are invalid.',
            });
        }

        await client.query('BEGIN');

        // Delete existing answers for this user
        await client.query('DELETE FROM user_security_answers WHERE user_id = $1', [req.user.userId]);

        // Insert new answers (hashed), reusing kept hashes
        for (const answer of answers) {
            const text = (answer.answer || '').trim();
            const hashedAnswer = text.length === 0
                ? existingHashes.get(Number(answer.questionId))
                : await bcrypt.hash(text.toLowerCase(), BCRYPT_ROUNDS);

            await client.query(
                'INSERT INTO user_security_answers (user_id, question_id, answer_hash) VALUES ($1, $2, $3)',
                [req.user.userId, answer.questionId, hashedAnswer]
            );
        }

        // Update user enrollment status
        await client.query(
            'UPDATE users SET security_questions_set = TRUE, updated_at = NOW() WHERE id = $1',
            [req.user.userId]
        );

        // Check if fully enrolled (both security questions and TOTP)
        await updateEnrollmentStatus(client, req.user.userId);

        await client.query('COMMIT');

        await logAudit(req.user.userId, req.user.username, 'enrollment', 'security_questions', req, true);

        res.json({
            success: true,
            message: 'Security questions saved successfully.',
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[Enrollment] Submit security questions error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to save security questions.',
        });
    } finally {
        client.release();
    }
}

/**
 * POST /api/enrollment/totp/setup
 * Generate a new TOTP secret and QR code for the user.
 */
async function setupTOTP(req, res) {
    try {
        const current = await db.query('SELECT totp_enabled FROM users WHERE id = $1', [req.user.userId]);
        if (current.rows[0]?.totp_enabled && !(await confirmCurrentPassword(req, res, 'totp'))) return;

        const secret = totpService.generateSecret();
        const qrCodeDataUrl = await totpService.generateQRCode(secret, req.user.username);

        // Staged until verified, so an existing authenticator keeps working if the user abandons setup
        const encryptedSecret = totpService.encryptSecret(secret);

        await db.query(
            'UPDATE users SET totp_pending_secret = $1, updated_at = NOW() WHERE id = $2',
            [encryptedSecret, req.user.userId]
        );

        res.json({
            success: true,
            data: {
                qrCode: qrCodeDataUrl,
                secret, // Allow manual entry if QR scanning fails
                message: 'Scan the QR code with your authenticator app, then verify with a code.',
            },
        });
    } catch (err) {
        console.error('[Enrollment] TOTP setup error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to set up TOTP.',
        });
    }
}

/**
 * POST /api/enrollment/totp/verify
 * Verify TOTP setup by checking a test code.
 * Body: { code: "123456" }
 */
async function verifyTOTPSetup(req, res) {
    try {
        const { code } = req.body;

        if (!code || code.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Please enter a valid 6-digit code.',
            });
        }

        // Get the stored (encrypted) secret
        const result = await db.query(
            'SELECT totp_pending_secret, totp_enabled FROM users WHERE id = $1',
            [req.user.userId]
        );

        if (result.rows.length === 0 || !result.rows[0].totp_pending_secret) {
            return res.status(400).json({
                success: false,
                message: 'TOTP has not been set up. Please start the setup process first.',
            });
        }

        const wasEnabled = result.rows[0].totp_enabled;
        const secret = totpService.decryptSecret(result.rows[0].totp_pending_secret);
        const step = totpService.verifyTokenStep(code, secret);
        const isValid = step !== null;

        if (!isValid) {
            return res.status(400).json({
                success: false,
                message: 'Invalid code. Please try again with a fresh code from your authenticator app.',
            });
        }

        // Enable TOTP
        const client = await db.getClient();
        try {
            await client.query('BEGIN');
            // Promote only if the pending secret is unchanged, and start replay tracking at this step
            const promoted = await client.query(
                `UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL,
                        totp_enabled = TRUE, totp_last_used_step = $2, updated_at = NOW()
                 WHERE id = $1 AND totp_pending_secret = $3 RETURNING id`,
                [req.user.userId, step, result.rows[0].totp_pending_secret]
            );
            if (promoted.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({
                    success: false,
                    message: 'Authenticator setup changed in another session. Please start again.',
                });
            }
            await updateEnrollmentStatus(client, req.user.userId);
            await client.query('COMMIT');
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }

        await logAudit(req.user.userId, req.user.username, wasEnabled ? 'totp_replaced' : 'enrollment', 'totp', req, true);

        res.json({
            success: true,
            message: wasEnabled
                ? 'New authenticator verified. Your previous device no longer works.'
                : 'Authenticator app verified and enabled successfully.',
        });
    } catch (err) {
        console.error('[Enrollment] TOTP verify error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to verify TOTP code.',
        });
    }
}

/**
 * GET /api/enrollment/status
 * Check the user's enrollment completion status.
 */
async function getStatus(req, res) {
    try {
        const result = await db.query(
            'SELECT is_enrolled, totp_enabled, security_questions_set FROM users WHERE id = $1',
            [req.user.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found.',
            });
        }

        const user = result.rows[0];

        res.json({
            success: true,
            data: {
                isEnrolled: user.is_enrolled,
                totpEnabled: user.totp_enabled,
                securityQuestionsSet: user.security_questions_set,
                steps: {
                    securityQuestions: user.security_questions_set ? 'complete' : 'pending',
                    totp: user.totp_enabled ? 'complete' : 'pending',
                },
            },
        });
    } catch (err) {
        console.error('[Enrollment] Status error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to check enrollment status.',
        });
    }
}

/**
 * Update the is_enrolled flag based on individual enrollment steps.
 */
async function updateEnrollmentStatus(client, userId) {
    const result = await client.query(
        'SELECT security_questions_set, totp_enabled FROM users WHERE id = $1',
        [userId]
    );

    if (result.rows.length > 0) {
        const user = result.rows[0];
        const isEnrolled = user.security_questions_set && user.totp_enabled;

        await client.query(
            'UPDATE users SET is_enrolled = $1, updated_at = NOW() WHERE id = $2',
            [isEnrolled, userId]
        );
    }
}

module.exports = {
    getQuestions,
    getMyQuestions,
    submitSecurityQuestions,
    setupTOTP,
    verifyTOTPSetup,
    getStatus,
};
