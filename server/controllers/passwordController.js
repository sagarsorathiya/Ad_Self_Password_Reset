const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const config = require('../config/default');
const db = require('../config/db');
const ldapService = require('../services/ldapService');
const totpService = require('../services/totpService');
const passwordExceptionService = require('../services/passwordExceptionService');
const { logAudit } = require('./authController');

const INCORRECT_ANSWERS_MESSAGE = 'One or more answers are incorrect. Please try again.';
const INVALID_CODE_MESSAGE = 'Invalid code. Please try again with a fresh code from your authenticator app.';
const DUMMY_ANSWER_HASH = bcrypt.hashSync('decoy-answer', 12);

// Stable per-username pseudo-random questions, so unknown/unenrolled accounts look like real ones
async function decoyQuestions(username) {
    const active = await db.query('SELECT id, question_text FROM security_questions WHERE is_active = TRUE');
    const key = String(username).toLowerCase();
    return active.rows
        .map((row) => ({ row, rank: crypto.createHmac('sha256', config.jwt.secret).update(`${key}:${row.id}`).digest('hex') }))
        .sort((a, b) => (a.rank < b.rank ? -1 : 1))
        .slice(0, 3)
        .map(({ row }) => row);
}

/**
 * POST /api/password/change
 * Change password for an authenticated user.
 * Body: { currentPassword, newPassword, confirmPassword }
 */
async function changePassword(req, res) {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password, new password, and confirmation are required.',
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'New password and confirmation do not match.',
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters long.',
            });
        }

        if (currentPassword === newPassword) {
            return res.status(400).json({
                success: false,
                message: 'New password must be different from the current password.',
            });
        }

        const violation = await passwordExceptionService.findViolation(newPassword);
        if (violation) {
            await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, false, 'Blocked by password exception list');
            return res.status(400).json({ success: false, message: exceptionMessage(violation) });
        }

        // Change password in AD (verifies current password first)
        await ldapService.changePasswordWithOld(req.user.dn, currentPassword, newPassword);

        await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, true);

        res.json({
            success: true,
            message: 'Password changed successfully. Please log in with your new password.',
        });
    } catch (err) {
        await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, false, err.message);

        if (err.message.includes('password policy') || err.message.includes('052D')) {
            return res.status(400).json({
                success: false,
                message: 'Password does not meet the domain password policy requirements. Ensure it meets complexity, length, and history requirements.',
            });
        }

        if (err.message === 'Invalid credentials') {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect.',
            });
        }

        console.error('[Password] Change error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to change password. Please try again.',
        });
    }
}

/**
 * POST /api/password/reset/verify-user
 * Step 1 of reset flow: Verify the username exists and is enrolled.
 * Body: { username }
 */
async function verifyUser(req, res) {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required.',
            });
        }

        // Check if user exists in AD
        const adUser = await ldapService.findUser(username);
        if (!adUser) {
            // Don't reveal whether user exists or not
            return res.status(400).json({
                success: false,
                message: 'Unable to verify your identity. Please ensure you have completed portal enrollment.',
            });
        }

        // Check if user is enrolled in our portal
        const result = await db.query(
            'SELECT id, is_enrolled, totp_enabled, security_questions_set, locked FROM users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0 || !result.rows[0].is_enrolled) {
            return res.status(400).json({
                success: false,
                message: 'Unable to verify your identity. Please ensure you have completed portal enrollment.',
            });
        }

        const dbUser = result.rows[0];

        if (dbUser.locked) {
            return res.status(403).json({
                success: false,
                message: 'Your account has been locked. Please contact your administrator.',
            });
        }

        // Return available verification methods (per RESET_POLICY)
        const policy = config.reset.policy;
        const methods = [];
        if (policy === 'both') {
            if (dbUser.security_questions_set && dbUser.totp_enabled) methods.push('security_questions', 'totp');
        } else {
            if (policy === 'either' && dbUser.security_questions_set) methods.push('security_questions');
            if (dbUser.totp_enabled) methods.push('totp');
        }

        if (methods.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Unable to verify your identity. Please ensure you have completed portal enrollment.',
            });
        }

        res.json({
            success: true,
            data: {
                username,
                policy,
                availableMethods: methods,
                message: 'User verified. Please choose a verification method.',
            },
        });
    } catch (err) {
        console.error('[Password] Verify user error:', err);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/password/reset/get-questions
 * Get the user's security questions (without answers) for the reset flow.
 * Body: { username }
 */
async function getUserQuestions(req, res) {
    try {
        const { username } = req.body;

        if (typeof username !== 'string' || !username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required.',
            });
        }

        const result = await db.query(
            `SELECT sq.id, sq.question_text
             FROM user_security_answers usa
             JOIN security_questions sq ON sq.id = usa.question_id
             JOIN users u ON u.id = usa.user_id
             WHERE u.username = $1 AND u.is_enrolled = TRUE
             ORDER BY usa.id ASC`,
            [username]
        );

        res.json({
            success: true,
            data: result.rows.length > 0 ? result.rows : await decoyQuestions(username),
        });
    } catch (err) {
        console.error('[Password] Get user questions error:', err);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/password/reset/verify-questions
 * Step 2a: Verify security question answers.
 * Body: { username, answers: [{ questionId: 1, answer: "..." }, ...] }
 */
async function verifySecurityQuestions(req, res) {
    try {
        const { username, answers } = req.body;

        if (config.reset.policy === 'totp_only') {
            return res.status(400).json({ success: false, message: 'Please verify with your authenticator app.' });
        }

        if (typeof username !== 'string' || !username || !Array.isArray(answers) || answers.length !== 3) {
            return res.status(400).json({
                success: false,
                message: 'Username and 3 answers are required.',
            });
        }

        // Get user
        const userResult = await db.query('SELECT id, locked FROM users WHERE username = $1 AND is_enrolled = TRUE', [username]);
        if (userResult.rows.length === 0) {
            // Same work and response as a wrong answer, so unknown users can't be distinguished
            await bcrypt.compare('timing-equalizer', DUMMY_ANSWER_HASH);
            return res.status(400).json({
                success: false,
                message: INCORRECT_ANSWERS_MESSAGE,
            });
        }

        const dbUser = userResult.rows[0];

        if (dbUser.locked) {
            return res.status(403).json({
                success: false,
                message: 'Your account has been locked. Please contact your administrator.',
            });
        }

        // Check lockout
        if (await isLockedOut(dbUser.id)) {
            return res.status(429).json({
                success: false,
                message: 'Too many failed attempts. Please try again later.',
            });
        }

        // Get stored answers
        const storedAnswers = await db.query(
            'SELECT question_id, answer_hash FROM user_security_answers WHERE user_id = $1',
            [dbUser.id]
        );

        const storedMap = new Map();
        for (const row of storedAnswers.rows) {
            storedMap.set(row.question_id, row.answer_hash);
        }

        // Every stored question must be answered exactly once
        const answeredIds = new Set(answers.map((a) => Number(a?.questionId)));
        let allCorrect = storedMap.size > 0
            && answeredIds.size === answers.length
            && answeredIds.size === storedMap.size
            && [...answeredIds].every((id) => storedMap.has(id));

        for (const answer of allCorrect ? answers : []) {
            const storedHash = storedMap.get(Number(answer.questionId));
            if (!storedHash || typeof answer.answer !== 'string') {
                allCorrect = false;
                break;
            }

            const normalizedAnswer = answer.answer.trim().toLowerCase();
            const isMatch = await bcrypt.compare(normalizedAnswer, storedHash);
            if (!isMatch) {
                allCorrect = false;
                break;
            }
        }

        if (!allCorrect) {
            await incrementFailedAttempts(dbUser.id);
            await logAudit(dbUser.id, username, 'password_reset_verify', 'security_questions', req, false, 'Incorrect answers');

            return res.status(400).json({
                success: false,
                message: 'One or more answers are incorrect. Please try again.',
            });
        }

        if (config.reset.policy === 'both') {
            // Second factor still required; failed-attempt counter is only cleared after full success
            const stepToken = jwt.sign(
                { type: 'reset_step', userId: dbUser.id, username, method: 'security_questions' },
                config.jwt.secret,
                { expiresIn: '5m', algorithm: 'HS256' }
            );
            await logAudit(dbUser.id, username, 'password_reset_verify', 'security_questions', req, true, 'Step 1 of 2');
            return res.json({
                success: true,
                data: { stepToken, nextStep: 'totp', message: 'Answers verified. Now enter your authenticator code.' },
            });
        }

        // Reset failed attempts
        await db.query(
            'UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = $1',
            [dbUser.id]
        );

        // Generate a single-use reset token
        const resetToken = generateResetToken(dbUser.id, username, 'security_questions');

        await logAudit(dbUser.id, username, 'password_reset_verify', 'security_questions', req, true);

        res.json({
            success: true,
            data: {
                resetToken,
                message: 'Identity verified. You may now set a new password.',
            },
        });
    } catch (err) {
        console.error('[Password] Verify questions error:', err);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/password/reset/verify-totp
 * Step 2b: Verify TOTP code.
 * Body: { username, code: "123456" }
 */
async function verifyTOTP(req, res) {
    try {
        const { username, code, stepToken } = req.body;

        if (typeof username !== 'string' || !username || typeof code !== 'string' || code.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Username and a valid 6-digit code are required.',
            });
        }

        // Get user
        const userResult = await db.query(
            'SELECT id, totp_secret, totp_enabled, locked FROM users WHERE username = $1',
            [username]
        );

        if (userResult.rows.length === 0 || !userResult.rows[0].totp_enabled) {
            return res.status(400).json({
                success: false,
                message: INVALID_CODE_MESSAGE,
            });
        }

        // 'both' policy: the TOTP step is only accepted after the questions step for the same user
        if (config.reset.policy === 'both') {
            let step;
            try {
                step = jwt.verify(String(stepToken || ''), config.jwt.secret, { algorithms: ['HS256'] });
            } catch {
                step = null;
            }
            if (!step || step.type !== 'reset_step' || step.userId !== userResult.rows[0].id) {
                return res.status(400).json({
                    success: false,
                    code: 'STEP_REQUIRED',
                    message: 'Please answer your security questions first.',
                });
            }
        }

        const dbUser = userResult.rows[0];

        if (dbUser.locked) {
            return res.status(403).json({
                success: false,
                message: 'Your account has been locked. Please contact your administrator.',
            });
        }

        // Check lockout
        if (await isLockedOut(dbUser.id)) {
            return res.status(429).json({
                success: false,
                message: 'Too many failed attempts. Please try again later.',
            });
        }

        // Decrypt the stored secret and verify
        const secret = totpService.decryptSecret(dbUser.totp_secret);
        const step = totpService.verifyTokenStep(code, secret);
        const isValid = step !== null && await totpService.consumeStep(db, dbUser.id, step);

        if (!isValid) {
            await incrementFailedAttempts(dbUser.id);
            await logAudit(dbUser.id, username, 'password_reset_verify', 'totp', req, false, 'Invalid TOTP code');

            return res.status(400).json({
                success: false,
                message: 'Invalid code. Please try again with a fresh code from your authenticator app.',
            });
        }

        // Reset failed attempts
        await db.query(
            'UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = $1',
            [dbUser.id]
        );

        // Generate a single-use reset token
        const method = config.reset.policy === 'both' ? 'security_questions+totp' : 'totp';
        const resetToken = generateResetToken(dbUser.id, username, method);

        await logAudit(dbUser.id, username, 'password_reset_verify', method, req, true);

        res.json({
            success: true,
            data: {
                resetToken,
                message: 'Identity verified. You may now set a new password.',
            },
        });
    } catch (err) {
        console.error('[Password] Verify TOTP error:', err);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/password/reset/set-password
 * Step 3: Set a new password using the reset token.
 * Body: { resetToken, newPassword, confirmPassword }
 */
async function setPassword(req, res) {
    try {
        const { resetToken, newPassword, confirmPassword } = req.body;

        if (!resetToken || !newPassword || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Reset token, new password, and confirmation are required.',
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'New password and confirmation do not match.',
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters long.',
            });
        }

        // Verify the reset token
        let decoded;
        try {
            decoded = jwt.verify(resetToken, config.jwt.secret, { algorithms: ['HS256'] });
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(400).json({
                    success: false,
                    message: 'Reset link has expired. Please start the process again.',
                });
            }
            return res.status(400).json({
                success: false,
                message: 'Invalid reset token.',
            });
        }

        if (decoded.type !== 'password_reset') {
            return res.status(400).json({
                success: false,
                message: 'Invalid reset token.',
            });
        }

        // Checked before claiming the token so the user can retry with another password
        const violation = await passwordExceptionService.findViolation(newPassword);
        if (violation) {
            await logAudit(decoded.userId, decoded.username, 'password_reset', decoded.method || 'unknown', req, false, 'Blocked by password exception list');
            return res.status(400).json({ success: false, message: exceptionMessage(violation) });
        }

        // Claim the token atomically so concurrent requests cannot both use it
        const claim = await db.query(
            `INSERT INTO used_reset_tokens (token_jti, user_id, expires_at) VALUES ($1, $2, $3)
             ON CONFLICT (token_jti) DO NOTHING RETURNING id`,
            [decoded.jti, decoded.userId, new Date(decoded.exp * 1000)]
        );

        if (claim.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'This reset link has already been used. Please start the process again.',
            });
        }

        const releaseClaim = () => db.query('DELETE FROM used_reset_tokens WHERE token_jti = $1', [decoded.jti]);

        const adUser = await ldapService.findUser(decoded.username);
        if (!adUser) {
            await releaseClaim();
            return res.status(400).json({
                success: false,
                message: 'User not found in Active Directory.',
            });
        }

        try {
            await ldapService.changePassword(adUser.dn, newPassword);
        } catch (err) {
            // Let the user retry with a different password while the token is still valid
            await releaseClaim();
            await logAudit(decoded.userId, decoded.username, 'password_reset', decoded.method || 'unknown', req, false, err.message);
            throw err;
        }

        await logAudit(decoded.userId, decoded.username, 'password_reset', decoded.method || 'unknown', req, true);

        res.json({
            success: true,
            message: 'Password reset successfully. You may now log in with your new password.',
        });
    } catch (err) {
        console.error('[Password] Set password error:', err);

        if (err.message.includes('password policy') || err.message.includes('052D')) {
            return res.status(400).json({
                success: false,
                message: 'Password does not meet the domain password policy requirements.',
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to reset password. Please try again.',
        });
    }
}

// ---- Helper functions ----

function exceptionMessage({ term, match_type: matchType }) {
    return matchType === 'exact'
        ? 'This password is not allowed by your organization. Please choose a different password.'
        : `The new password must not contain "${term}" (or a look-alike such as letters replaced by numbers or symbols). Please choose a different password.`;
}

/**
 * Generate a single-use reset token (JWT with JTI).
 */
function generateResetToken(userId, username, method) {
    return jwt.sign(
        {
            userId,
            username,
            method,
            type: 'password_reset',
            jti: uuidv4(),
        },
        config.jwt.secret,
        { expiresIn: '10m' }
    );
}

/**
 * Check if a user is locked out due to too many failed attempts.
 */
async function isLockedOut(userId) {
    const result = await db.query(
        'SELECT failed_attempts, last_failed_attempt FROM users WHERE id = $1',
        [userId]
    );

    if (result.rows.length === 0) return false;

    const user = result.rows[0];
    if (user.failed_attempts < config.lockout.maxAttempts) return false;

    if (user.last_failed_attempt) {
        const lockoutEnd = new Date(user.last_failed_attempt).getTime() + config.lockout.lockoutDurationMs;
        if (Date.now() < lockoutEnd) return true;

        // Lockout has expired, reset
        await db.query(
            'UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = $1',
            [userId]
        );
    }

    return false;
}

/**
 * Increment failed attempt counter.
 */
async function incrementFailedAttempts(userId) {
    await db.query(
        'UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_attempt = NOW() WHERE id = $1',
        [userId]
    );
}

module.exports = {
    changePassword,
    verifyUser,
    getUserQuestions,
    verifySecurityQuestions,
    verifyTOTP,
    setPassword,
};
