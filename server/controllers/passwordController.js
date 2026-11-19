const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const config = require('../config/default');
const settingsService = require('../services/settingsService');
const db = require('../config/db');
const ldapService = require('../services/ldapService');
const totpService = require('../services/totpService');
const smsOtpService = require('../services/smsOtpService');
const mobileService = require('../services/mobileService');
const passwordExceptionService = require('../services/passwordExceptionService');
const passwordSyncService = require('../services/passwordSyncService');
const notificationService = require('../services/notificationService');
const sessionService = require('../services/sessionService');
const { isLockedOut: isAdLockedOut, resetBlockedForProtected } = require('../services/adPassword');
const passwordPolicyService = require('../services/passwordPolicyService');
const { logAudit } = require('./authController');

const INCORRECT_ANSWERS_MESSAGE = 'One or more answers are incorrect. Please try again.';
const INVALID_CODE_MESSAGE = 'Invalid code. Please try again with a fresh code from your authenticator app.';
const NOT_ENROLLED_MESSAGE = 'Unable to verify your identity. Please ensure you have completed portal enrollment.';
const LOCKED_MESSAGE = 'Your account has been locked. Please contact your administrator.';
const PROTECTED_MESSAGE = 'Password reset is not available for administrator accounts here. Please contact IT.';
const UNAVAILABLE_MESSAGE = 'The directory service is currently unavailable. Please try again later or contact IT support.';
const DUMMY_ANSWER_HASH = bcrypt.hashSync('decoy-answer', 12);
const UAC_ACCOUNT_DISABLED = 2;

function hideAccountState() {
    return settingsService.current().security.hideAccountState;
}

function isUnreachable(err) {
    return /unreachable|connection error/i.test(err?.message || '');
}

// Stable per-username pseudo-random questions, so unknown/unenrolled accounts look like real ones
async function decoyQuestions(username) {
    const active = await db.query('SELECT id, question_text FROM security_questions WHERE is_active = TRUE');
    const key = String(username).toLowerCase();
    return active.rows
        .map((row) => ({ row, rank: crypto.createHmac('sha256', config.jwt.secret).update(`${key}:${row.id}`).digest('hex') }))
        .sort((a, b) => (a.rank < b.rank ? -1 : 1))
        .slice(0, settingsService.current().security.questionCount)
        .map(({ row }) => row);
}

/**
 * GET /api/password/rules
 * The rules the change and reset pages show and check before AD is asked: the admin settings, tightened by the
 * domain policy when it can be read (a fine-grained policy for one user is applied at submit time).
 */
async function getRules(req, res) {
    const { passwordMinLength, passwordComplexity } = settingsService.current().security;
    const domain = await passwordPolicyService.domainRules();
    res.json({
        success: true,
        data: {
            minLength: Math.max(passwordMinLength, domain?.minLength || 0),
            complexity: domain ? domain.complexity : passwordComplexity,
            historyCount: domain?.historyLength || 0,
            minAgeDays: domain?.minAgeDays || 0,
        },
    });
}

// Shared checks for a new password; returns an error message or null
function newPasswordError(newPassword, confirmPassword) {
    if (newPassword !== confirmPassword) return 'New password and confirmation do not match.';
    const minLength = settingsService.current().security.passwordMinLength;
    if (newPassword.length < minLength) return `New password must be at least ${minLength} characters long.`;
    return null;
}

/**
 * POST /api/password/change
 * Change password for an authenticated user.
 * Body: { currentPassword, newPassword, confirmPassword }
 */
async function changePassword(req, res) {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        // Enrollment is mandatory before any password change (JWT isEnrolled can be stale)
        const enrolled = await db.query('SELECT is_enrolled FROM users WHERE id = $1', [req.user.userId]);
        if (!enrolled.rows[0]?.is_enrolled) {
            await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, false, 'Not enrolled');
            return res.status(403).json({
                success: false,
                message: 'Please set up your security questions and authenticator app before changing your password.',
                code: 'ENROLLMENT_REQUIRED',
            });
        }

        if (typeof currentPassword !== 'string' || !currentPassword
            || typeof newPassword !== 'string' || !newPassword || typeof confirmPassword !== 'string' || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password, new password, and confirmation are required.',
            });
        }

        const invalid = newPasswordError(newPassword, confirmPassword);
        if (invalid) return res.status(400).json({ success: false, message: invalid });

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

        // The DN is read now, not taken from the token: the account may have moved since sign-in
        const adUser = await ldapService.findUser(req.user.username);
        if (!adUser) {
            return res.status(404).json({ success: false, message: 'Your account was not found in Active Directory.' });
        }

        // Say exactly which rule fails, instead of AD's single "does not meet the policy"
        const policy = await passwordPolicyService.forUser(adUser);
        const problems = passwordPolicyService.checkAgainstPolicy(newPassword, policy, {
            username: adUser.sAMAccountName, displayName: adUser.displayName,
        });
        if (problems.length) {
            await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, false,
                `Policy check: ${problems.map((p) => p.rule).join(', ')}`);
            return policyResponse(res, problems);
        }

        // Nothing is written unless the second domain (if configured) is reachable
        const syncPlan = await passwordSyncService.prepare(req.user.username);

        // Change password in AD (verifies current password first)
        try {
            await ldapService.changePasswordWithOld(adUser.dn, currentPassword, newPassword);
        } catch (err) {
            if (!isPolicyError(err)) throw err;
            // Passed the rules above, so AD refused it for a rule only it can check: minimum age or history
            const reasons = passwordPolicyService.explainRejection({ policy, mode: 'change', pwdLastSet: adUser.pwdLastSet });
            await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, false,
                `${err.message}${reasons.length ? ` (likely: ${reasons.map((r) => r.rule).join(', ')})` : ''}`);
            return policyResponse(res, reasons);
        }

        await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, true);
        await revokeSessions(req.user.userId);

        const sync = await syncSecondary(syncPlan, newPassword, req.user.userId, req.user.username, 'authenticated', req);

        // Not awaited: a slow mail relay must not delay the answer
        notificationService.sendPasswordChangedAlert({
            userId: req.user.userId, username: req.user.username, method: 'authenticated', req, sync, adUser,
        });

        res.json({
            success: true,
            message: sync?.status === 'failed'
                ? syncFailureMessage(sync)
                : 'Password changed successfully. Please log in with your new password.',
            data: { sync: publicSyncResult(sync) },
        });
    } catch (err) {
        await logAudit(req.user.userId, req.user.username, 'password_change', 'authenticated', req, false, err.message);

        if (err instanceof passwordSyncService.SecondaryUnavailableError) {
            return res.status(503).json({ success: false, message: unavailableMessage(err) });
        }

        if (isPolicyError(err)) {
            return res.status(400).json({ success: false, message: policyErrorMessage() });
        }

        if (err.message === 'Invalid credentials' || err.message === 'Current password is incorrect') {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect.',
            });
        }

        if (err.message.startsWith('Insufficient access rights')) {
            return res.status(403).json({
                success: false,
                message: 'Your account cannot change its password here. Please contact IT.',
            });
        }

        if (isUnreachable(err)) {
            return res.status(503).json({ success: false, message: UNAVAILABLE_MESSAGE });
        }

        logHintsProblem(err);
        console.error('[Password] Change error:', err.message);
        res.status(500).json({
            success: false,
            message: 'Failed to change password. Please try again.',
        });
    }
}

// Methods offered without looking at the account: questions unless totp_only, plus every enabled factor
function methodsForPolicy(policy, factors) {
    const codes = [factors.totp && 'totp', factors.sms && 'sms'].filter(Boolean);
    return policy === 'totp_only' ? codes : ['security_questions', ...codes];
}

/**
 * POST /api/password/reset/verify-user
 * Step 1 of reset flow: Verify the username exists and is enrolled.
 * Body: { username }
 */
async function verifyUser(req, res) {
    try {
        const { username } = req.body;

        if (typeof username !== 'string' || !username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required.',
            });
        }

        const policy = settingsService.resetPolicy();
        const factors = settingsService.current().factors;

        // Same answer for every username: the later steps answer real and unknown accounts alike
        if (hideAccountState()) {
            return res.json({
                success: true,
                data: {
                    username,
                    policy,
                    availableMethods: methodsForPolicy(policy, factors),
                    mobileMasked: null,
                    // Tells the page to say "only works if you set it up"
                    generic: true,
                    message: 'Please choose a verification method.',
                },
            });
        }

        // Check if user exists in AD
        const adUser = await ldapService.findUser(username);
        if (!adUser || (parseInt(adUser.userAccountControl, 10) & UAC_ACCOUNT_DISABLED) !== 0) {
            return res.status(400).json({ success: false, message: NOT_ENROLLED_MESSAGE });
        }

        // A least-privilege service account cannot reset protected accounts: say so before any verification
        if (resetBlockedForProtected(adUser, ldapService.serviceAccountPrivileged?.() ?? null)) {
            return res.status(400).json({ success: false, code: 'PROTECTED_ACCOUNT', message: PROTECTED_MESSAGE });
        }

        // Check if user is enrolled in our portal
        const result = await db.query(
            `SELECT id, is_enrolled, totp_enabled, sms_enabled, security_questions_set, locked,
                    mobile_number, mobile_source, mobile_verified_hash
             FROM users WHERE LOWER(username) = LOWER($1)`,
            [username]
        );

        if (result.rows.length === 0 || !result.rows[0].is_enrolled) {
            return res.status(400).json({ success: false, message: NOT_ENROLLED_MESSAGE });
        }

        const dbUser = result.rows[0];

        if (dbUser.locked) {
            return res.status(403).json({ success: false, message: LOCKED_MESSAGE });
        }

        // Return available verification methods (per the reset policy and the enabled second factors)
        const mobile = factors.sms && dbUser.sms_enabled ? mobileService.resolve(dbUser, adUser) : null;

        // Second factors this user can actually use right now. SMS is still offered when the directory number
        // changed, so send-sms can explain why no code goes out (MOBILE_CHANGED)
        const secondFactors = [];
        if (factors.totp && dbUser.totp_enabled) secondFactors.push('totp');
        if (mobile?.number || mobile?.changed) secondFactors.push('sms');

        const methods = [];
        if (policy === 'both') {
            // Questions first, then any one second factor
            if (dbUser.security_questions_set && secondFactors.length > 0) {
                methods.push('security_questions', ...secondFactors);
            }
        } else {
            if (policy === 'either' && dbUser.security_questions_set) methods.push('security_questions');
            methods.push(...secondFactors);
        }

        if (methods.length === 0) {
            return res.status(400).json({ success: false, message: NOT_ENROLLED_MESSAGE });
        }

        res.json({
            success: true,
            data: {
                // AD's own spelling, so every later step and the reset token carry the canonical name
                username: adUser.sAMAccountName,
                policy,
                availableMethods: methods,
                // Where an SMS code would go, so the user can tell it is the right phone
                mobileMasked: mobile?.number ? mobileService.mask(mobile.number) : null,
                message: 'User verified. Please choose a verification method.',
            },
        });
    } catch (err) {
        if (isUnreachable(err)) return res.status(503).json({ success: false, message: UNAVAILABLE_MESSAGE });
        console.error('[Password] Verify user error:', err.message);
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
             WHERE LOWER(u.username) = LOWER($1) AND u.is_enrolled = TRUE
             ORDER BY usa.id ASC`,
            [username]
        );

        res.json({
            success: true,
            data: result.rows.length > 0 ? result.rows : await decoyQuestions(username),
        });
    } catch (err) {
        console.error('[Password] Get user questions error:', err.message);
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
        const policy = settingsService.resetPolicy();

        if (policy === 'totp_only') {
            return res.status(400).json({ success: false, message: 'Please verify with your authenticator app.' });
        }

        // The count is not fixed here: every stored question must be answered (checked below), and users
        // enrolled under an older setting can still have more than the current number.
        if (typeof username !== 'string' || !username || !Array.isArray(answers)
            || answers.length < 1 || answers.length > 10) {
            return res.status(400).json({
                success: false,
                message: 'Username and your security answers are required.',
            });
        }

        // Get user
        const userResult = await db.query(
            'SELECT id, username, locked, totp_enabled, sms_enabled FROM users WHERE LOWER(username) = LOWER($1) AND is_enrolled = TRUE',
            [username]
        );
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
            return res.status(403).json({ success: false, message: LOCKED_MESSAGE });
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
            await logAudit(dbUser.id, dbUser.username, 'password_reset_verify', 'security_questions', req, false, 'Incorrect answers');

            return res.status(400).json({
                success: false,
                message: INCORRECT_ANSWERS_MESSAGE,
            });
        }

        if (policy === 'both') {
            // Second factor still required; failed-attempt counter is only cleared after full success
            const stepToken = jwt.sign(
                { type: 'reset_step', userId: dbUser.id, username: dbUser.username, method: 'security_questions' },
                config.jwt.secret,
                { expiresIn: '5m', algorithm: 'HS256' }
            );
            const factors = settingsService.current().factors;
            const nextSteps = [];
            if (factors.totp && dbUser.totp_enabled) nextSteps.push('totp');
            if (factors.sms && dbUser.sms_enabled) nextSteps.push('sms');

            await logAudit(dbUser.id, dbUser.username, 'password_reset_verify', 'security_questions', req, true, 'Step 1 of 2');
            return res.json({
                success: true,
                data: {
                    stepToken,
                    nextSteps,
                    nextStep: nextSteps[0] || 'totp',
                    message: 'Answers verified. Now enter your one-time code.',
                },
            });
        }

        // Reset failed attempts
        await db.query(
            'UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = $1',
            [dbUser.id]
        );

        // Generate a single-use reset token
        const resetToken = generateResetToken(dbUser.id, dbUser.username, 'security_questions');

        await logAudit(dbUser.id, dbUser.username, 'password_reset_verify', 'security_questions', req, true);

        res.json({
            success: true,
            data: {
                resetToken,
                message: 'Identity verified. You may now set a new password.',
            },
        });
    } catch (err) {
        console.error('[Password] Verify questions error:', err.message);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/password/reset/verify-totp
 * Step 2b: Verify TOTP code.
 * Body: { username, code: "123456", stepToken? }
 */
async function verifyTOTP(req, res) {
    try {
        const { username, code, stepToken } = req.body;
        const policy = settingsService.resetPolicy();

        if (typeof username !== 'string' || !username || typeof code !== 'string' || code.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Username and a valid 6-digit code are required.',
            });
        }

        // 'both' policy: checked before any lookup, so the answer is the same for real and unknown accounts
        if (!stepTokenAccepted(stepToken, username, policy)) {
            return res.status(400).json({
                success: false,
                code: 'STEP_REQUIRED',
                message: 'Please answer your security questions first.',
            });
        }

        // Get user
        const userResult = await db.query(
            'SELECT id, username, totp_secret, totp_enabled, locked FROM users WHERE LOWER(username) = LOWER($1)',
            [username]
        );

        if (userResult.rows.length === 0 || !userResult.rows[0].totp_enabled) {
            return res.status(400).json({
                success: false,
                message: INVALID_CODE_MESSAGE,
            });
        }

        const dbUser = userResult.rows[0];

        if (dbUser.locked) {
            return res.status(403).json({ success: false, message: LOCKED_MESSAGE });
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
            await logAudit(dbUser.id, dbUser.username, 'password_reset_verify', 'totp', req, false, 'Invalid TOTP code');

            return res.status(400).json({
                success: false,
                message: INVALID_CODE_MESSAGE,
            });
        }

        // Reset failed attempts
        await db.query(
            'UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = $1',
            [dbUser.id]
        );

        // Generate a single-use reset token
        const method = policy === 'both' ? 'security_questions+totp' : 'totp';
        const resetToken = generateResetToken(dbUser.id, dbUser.username, method);

        await logAudit(dbUser.id, dbUser.username, 'password_reset_verify', method, req, true);

        res.json({
            success: true,
            data: {
                resetToken,
                message: 'Identity verified. You may now set a new password.',
            },
        });
    } catch (err) {
        console.error('[Password] Verify TOTP error:', err.message);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
        });
    }
}

/**
 * POST /api/password/reset/send-sms
 * Step 2c (part 1): text a one-time code to the number held for the account.
 * Body: { username, stepToken? }
 *
 * Answers the same way for every username: an account that does not exist, is not enrolled or has no
 * mobile number gets a plausible masked number and no message, so the page cannot be used to find out
 * who has an account here.
 */
async function sendResetSMS(req, res) {
    const { username, stepToken } = req.body || {};
    const decoy = () => res.json({
        success: true,
        data: {
            mobileMasked: mobileService.decoyMask(username),
            resendAfter: smsOtpService.RESEND_COOLDOWN_SECONDS,
            expiresInMinutes: smsOtpService.CODE_TTL_MINUTES,
        },
    });
    let dbUser = null;

    try {
        if (typeof username !== 'string' || !username) {
            return res.status(400).json({ success: false, message: 'Username is required.' });
        }
        if (!settingsService.current().factors.sms) {
            return res.status(400).json({ success: false, message: 'SMS codes are not available.' });
        }
        if (!stepTokenAccepted(stepToken, username, settingsService.resetPolicy())) {
            return res.status(400).json({
                success: false,
                code: 'STEP_REQUIRED',
                message: 'Please answer your security questions first.',
            });
        }

        const userResult = await db.query(
            `SELECT id, username, sms_enabled, locked, mobile_number, mobile_source, mobile_verified_hash
             FROM users WHERE LOWER(username) = LOWER($1) AND is_enrolled = TRUE`,
            [username]
        );
        if (userResult.rows.length === 0 || !userResult.rows[0].sms_enabled) return decoy();

        dbUser = userResult.rows[0];

        if (dbUser.locked) {
            return res.status(403).json({ success: false, message: LOCKED_MESSAGE });
        }
        if (await isLockedOut(dbUser.id)) {
            return res.status(429).json({ success: false, message: 'Too many failed attempts. Please try again later.' });
        }

        const mobile = mobileService.resolve(dbUser, await ldapService.findUser(dbUser.username));
        if (mobile?.changed) {
            await logAudit(dbUser.id, dbUser.username, 'password_reset_sms', 'sms', req, false,
                'AD mobile number changed since it was verified; no code sent');
            if (hideAccountState()) return decoy();
            return res.status(409).json({
                success: false,
                code: 'MOBILE_CHANGED',
                message: 'The mobile number on your account changed after you set up text messages. '
                    + 'Use another method, or sign in and confirm the new number in Security Settings.',
            });
        }
        if (!mobile?.number) return decoy();

        const masked = mobileService.mask(mobile.number);
        const { resendAfter, gateway } = await smsOtpService.issue({
            userId: dbUser.id,
            purpose: 'reset',
            number: mobile.number,
            maskedNumber: masked,
        });
        await logAudit(dbUser.id, dbUser.username, 'password_reset_sms', 'sms', req, true,
            smsOtpService.sentDetail(masked, gateway));

        res.json({
            success: true,
            data: { mobileMasked: masked, resendAfter, expiresInMinutes: smsOtpService.CODE_TTL_MINUTES },
        });
    } catch (err) {
        if (err instanceof smsOtpService.CooldownError) {
            return res.status(429).json({
                success: false,
                code: 'SMS_COOLDOWN',
                message: err.message,
                data: { resendAfter: err.retryAfter },
            });
        }
        if (err instanceof smsOtpService.SmsLimitError) {
            return smsLimitResponse(err, dbUser, req, res);
        }
        console.error('[Password] Send reset SMS error:', err.message);
        res.status(502).json({
            success: false,
            message: 'We could not send the text message. Please try another method or contact your administrator.',
        });
    }
}

/**
 * Daily SMS cap reached (shared with enrolment): audited, and the portal-wide case is logged for the admins.
 */
async function smsLimitResponse(err, dbUser, req, res) {
    if (err.scope === 'total') console.error('[SMS] Portal-wide daily SMS limit reached');
    await logAudit(dbUser?.id ?? null, dbUser?.username, 'sms_limit', 'sms', req, false,
        err.scope === 'total' ? 'portal-wide limit' : 'per-user limit');
    return res.status(429).json({
        success: false,
        code: 'SMS_LIMIT',
        message: 'The daily limit for text messages has been reached. Please use another method or contact IT.',
    });
}

/**
 * POST /api/password/reset/verify-sms
 * Step 2c (part 2): check the code that was texted to the user.
 * Body: { username, code, stepToken? }
 */
async function verifySMS(req, res) {
    try {
        const { username, code, stepToken } = req.body || {};
        const policy = settingsService.resetPolicy();

        if (typeof username !== 'string' || !username || typeof code !== 'string' || code.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Username and a valid 6-digit code are required.',
            });
        }
        if (!stepTokenAccepted(stepToken, username, policy)) {
            return res.status(400).json({
                success: false,
                code: 'STEP_REQUIRED',
                message: 'Please answer your security questions first.',
            });
        }

        const userResult = await db.query(
            'SELECT id, username, sms_enabled, locked FROM users WHERE LOWER(username) = LOWER($1) AND is_enrolled = TRUE',
            [username]
        );
        // Same answer as a wrong code: an unknown account must not be distinguishable here either
        if (userResult.rows.length === 0 || !userResult.rows[0].sms_enabled) {
            return res.status(400).json({ success: false, message: smsOtpService.codeErrorMessage('mismatch') });
        }

        const dbUser = userResult.rows[0];

        if (dbUser.locked) {
            return res.status(403).json({ success: false, message: LOCKED_MESSAGE });
        }
        if (await isLockedOut(dbUser.id)) {
            return res.status(429).json({ success: false, message: 'Too many failed attempts. Please try again later.' });
        }

        const check = await smsOtpService.verify({ userId: dbUser.id, purpose: 'reset', code });
        if (!check.ok) {
            await incrementFailedAttempts(dbUser.id);
            await logAudit(dbUser.id, dbUser.username, 'password_reset_verify', 'sms', req, false, `Invalid SMS code (${check.reason})`);
            return res.status(400).json({ success: false, message: smsOtpService.codeErrorMessage(check.reason) });
        }

        // Enrolments from before number pinning: the number that just proved itself becomes the pinned one
        await db.query(
            `UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL,
                    mobile_verified_hash = COALESCE(mobile_verified_hash, $2)
             WHERE id = $1`,
            [dbUser.id, check.numberHash]
        );

        const method = policy === 'both' ? 'security_questions+sms' : 'sms';
        const resetToken = generateResetToken(dbUser.id, dbUser.username, method);

        await logAudit(dbUser.id, dbUser.username, 'password_reset_verify', method, req, true);

        res.json({
            success: true,
            data: { resetToken, message: 'Identity verified. You may now set a new password.' },
        });
    } catch (err) {
        console.error('[Password] Verify SMS error:', err.message);
        res.status(500).json({ success: false, message: 'An error occurred. Please try again.' });
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

        if (!resetToken || typeof newPassword !== 'string' || !newPassword
            || typeof confirmPassword !== 'string' || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Reset token, new password, and confirmation are required.',
            });
        }

        const invalid = newPasswordError(newPassword, confirmPassword);
        if (invalid) return res.status(400).json({ success: false, message: invalid });

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

        const method = decoded.method || 'unknown';
        const fail = (status, message, details) => logAudit(decoded.userId, decoded.username, 'password_reset', method, req, false, details || message)
            .then(() => res.status(status).json({ success: false, message }));

        // Checked before claiming the token so the user can retry with another password
        const violation = await passwordExceptionService.findViolation(newPassword);
        if (violation) {
            return fail(400, exceptionMessage(violation), 'Blocked by password exception list');
        }

        let syncPlan;
        try {
            syncPlan = await passwordSyncService.prepare(decoded.username);
        } catch (err) {
            if (!(err instanceof passwordSyncService.SecondaryUnavailableError)) throw err;
            return fail(503, unavailableMessage(err), err.message);
        }

        const adUser = await ldapService.findUser(decoded.username);
        if (!adUser) {
            return res.status(400).json({
                success: false,
                message: 'User not found in Active Directory.',
            });
        }

        // Which rule fails, checked before the token is claimed so the user can simply try another password
        const policy = await passwordPolicyService.forUser(adUser);
        const problems = passwordPolicyService.checkAgainstPolicy(newPassword, policy, {
            username: adUser.sAMAccountName, displayName: adUser.displayName,
        });
        if (problems.length) {
            await logAudit(decoded.userId, decoded.username, 'password_reset', method, req, false,
                `Policy check: ${problems.map((p) => p.rule).join(', ')}`);
            return policyResponse(res, problems);
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

        // The account may have changed in the minutes since verification
        if ((parseInt(adUser.userAccountControl, 10) & UAC_ACCOUNT_DISABLED) !== 0) {
            await releaseClaim();
            return fail(403, 'This account is disabled. Please contact IT.', 'Account disabled in AD');
        }
        const portal = await db.query('SELECT locked FROM users WHERE id = $1', [decoded.userId]);
        if (portal.rows[0]?.locked) {
            await releaseClaim();
            return fail(403, LOCKED_MESSAGE, 'Account locked in portal');
        }

        try {
            await ldapService.changePassword(adUser.dn, newPassword);
        } catch (err) {
            // Let the user retry with a different password while the token is still valid
            await releaseClaim();
            if (isPolicyError(err)) {
                // Passed the portal's checks, so AD refused it for history (the minimum age does not apply to a reset)
                const reasons = passwordPolicyService.explainRejection({ policy, mode: 'reset' });
                await logAudit(decoded.userId, decoded.username, 'password_reset', method, req, false,
                    `${err.message}${reasons.length ? ` (likely: ${reasons.map((r) => r.rule).join(', ')})` : ''}`);
                return policyResponse(res, reasons);
            }
            await logAudit(decoded.userId, decoded.username, 'password_reset', method, req, false, err.message);
            throw err;
        }

        await logAudit(decoded.userId, decoded.username, 'password_reset', method, req, true);
        await revokeSessions(decoded.userId);

        // A forgotten password often comes with a lockout: clear it too (needs Write lockoutTime)
        let unlocked = false;
        if (isAdLockedOut(adUser) || parseInt(adUser.lockoutTime, 10) > 0) {
            try {
                await ldapService.unlockAccount(adUser.dn);
                unlocked = true;
                await logAudit(decoded.userId, decoded.username, 'account_unlock', method, req, true, 'Unlocked after password reset');
            } catch (err) {
                console.warn(`[Password] Unlock after reset failed for ${decoded.username}: ${err.message}`);
                await logAudit(decoded.userId, decoded.username, 'account_unlock', method, req, false, err.message);
            }
        }

        const sync = await syncSecondary(syncPlan, newPassword, decoded.userId, decoded.username, method, req);

        // Not awaited: a slow mail relay must not delay the answer
        notificationService.sendPasswordChangedAlert({
            userId: decoded.userId, username: decoded.username, method, req, sync, adUser,
        });

        res.json({
            success: true,
            message: sync?.status === 'failed'
                ? syncFailureMessage(sync)
                : 'Password reset successfully. You may now log in with your new password.',
            data: { sync: publicSyncResult(sync), unlocked },
        });
    } catch (err) {
        if (isPolicyError(err)) {
            return res.status(400).json({ success: false, message: policyErrorMessage() });
        }
        if (err.message.startsWith('Insufficient access rights')) {
            return res.status(403).json({ success: false, code: 'PROTECTED_ACCOUNT', message: PROTECTED_MESSAGE });
        }
        if (isUnreachable(err)) {
            return res.status(503).json({ success: false, message: UNAVAILABLE_MESSAGE });
        }

        logHintsProblem(err);
        console.error('[Password] Set password error:', err.message);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password. Please try again.',
        });
    }
}

// ---- Helper functions ----

function isPolicyError(err) {
    return /password policy|052D/.test(err?.message || '');
}

function policyErrorMessage() {
    return 'Password does not meet the domain password policy. Use the required length and character types, '
        + 'do not reuse a recent password, and note that a password cannot be changed again too soon after the last change.';
}

/**
 * 400 PASSWORD_POLICY with the specific reasons in data.problems (the page lists them under the field).
 * Without a specific reason (policy unreadable) the general wording is used, as before.
 */
function policyResponse(res, problems) {
    return res.status(400).json({
        success: false,
        code: 'PASSWORD_POLICY',
        message: problems.length ? passwordPolicyService.summarize(problems) : policyErrorMessage(),
        data: { problems },
    });
}

function logHintsProblem(err) {
    if (/does not support the password policy hints/.test(err?.message || '')) {
        console.error('[Password] DC lacks policy hints; set AD_RESET_POLICY_HINTS=false or upgrade the DC');
    }
}

// The password changed: every open session ends (the password may have been changed because of them)
async function revokeSessions(userId) {
    try {
        await sessionService.revokeAll(userId);
    } catch (err) {
        console.error('[Password] Session revoke failed:', err.message);
    }
}

/**
 * Write the new password to the second domain (after the first domain accepted it) and audit the outcome.
 */
async function syncSecondary(plan, newPassword, userId, username, method, req) {
    const sync = await passwordSyncService.apply(plan, newPassword);
    if (!sync) return null;

    const details = {
        synced: `${sync.domain}: password updated`,
        not_found: sync.reason
            ? `${sync.domain}: ${sync.reason}, skipped`
            : `${sync.domain}: no account with this username, skipped`,
        failed: `${sync.domain}: ${sync.error}`,
    }[sync.status];
    await logAudit(userId, username, 'password_sync', method, req, sync.status !== 'failed', details);
    if (sync.status === 'failed') console.error(`[Password] Sync to ${sync.domain} failed: ${sync.error}`);
    return sync;
}

// What the browser may see: no server addresses or raw LDAP errors
function publicSyncResult(sync) {
    return sync ? { domain: sync.domain, status: sync.status } : null;
}

function syncFailureMessage(sync) {
    const reason = /password policy|052D/.test(sync.error)
        ? `it does not meet the ${sync.domain} password policy`
        : `${sync.domain} could not be updated`;
    return `Your password was changed in ${config.ad.name}, but NOT in ${sync.domain} because ${reason}. `
        + 'Use Forgot password to set a password that meets the requirements of both, or contact IT.';
}

function unavailableMessage(err) {
    return `${err.domain} is currently unavailable, so your password was not changed. Please try again later.`;
}

function exceptionMessage({ term, match_type: matchType }) {
    return matchType === 'exact'
        ? 'This password is not allowed by your organization. Please choose a different password.'
        : `The new password must not contain "${term}" (or a look-alike such as letters replaced by numbers or symbols). Please choose a different password.`;
}

/**
 * Under the 'both' policy a second factor only counts once the security questions have been answered,
 * proved by the short-lived reset_step token issued there. Always true under the other policies.
 * Matched by username, not user id, so it can be checked before any database lookup.
 */
function stepTokenAccepted(stepToken, username, policy) {
    if (policy !== 'both') return true;
    try {
        const step = jwt.verify(String(stepToken || ''), config.jwt.secret, { algorithms: ['HS256'] });
        return step.type === 'reset_step' && String(step.username).toLowerCase() === String(username).toLowerCase();
    } catch {
        return false;
    }
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

    const { lockoutAttempts, lockoutMinutes } = settingsService.current().security;
    const user = result.rows[0];
    if (user.failed_attempts < lockoutAttempts) return false;

    if (user.last_failed_attempt) {
        const lockoutEnd = new Date(user.last_failed_attempt).getTime() + lockoutMinutes * 60 * 1000;
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
    getRules,
    verifyUser,
    getUserQuestions,
    verifySecurityQuestions,
    verifyTOTP,
    sendResetSMS,
    smsLimitResponse,
    verifySMS,
    setPassword,
};
