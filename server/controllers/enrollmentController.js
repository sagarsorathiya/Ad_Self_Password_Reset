const bcrypt = require('bcryptjs');
const db = require('../config/db');
const settingsService = require('../services/settingsService');
const totpService = require('../services/totpService');
const smsOtpService = require('../services/smsOtpService');
const smsService = require('../services/smsService');
const mobileService = require('../services/mobileService');
const ldapService = require('../services/ldapService');
const cryptoService = require('../services/cryptoService');
const reauthService = require('../services/reauthService');
const notificationService = require('../services/notificationService');
const { resetBlockedForProtected } = require('../services/adPassword');
const { logAudit } = require('./authController');
const { smsLimitResponse } = require('./passwordController');

const BCRYPT_ROUNDS = 12;
// First enrolment needs a password proved within this many seconds (a fresh sign-in or /api/auth/reauth)
const RECENT_AUTH_SECONDS = 15 * 60;

// Replacing an existing factor must prove password knowledge, so a stolen session can't swap in attacker-controlled factors.
async function confirmCurrentPassword(req, res, method) {
    const check = await reauthService.verifyPassword(req.user.username, req.body?.currentPassword);
    if (check === 'ok') return true;
    if (check === 'missing') {
        res.status(401).json({
            success: false,
            code: 'REAUTH_REQUIRED',
            message: 'Please confirm your current password to change existing recovery settings.',
        });
        return false;
    }
    await logAudit(req.user.userId, req.user.username, 'reauth', method, req, false, check);
    res.status(check === 'unavailable' ? 503 : 401).json({
        success: false,
        code: 'REAUTH_FAILED',
        message: check === 'unavailable' ? 'The directory service is currently unavailable.' : 'Current password is incorrect.',
    });
    return false;
}

/**
 * An account that is not enrolled yet may set up its first factors without typing the password again, but only
 * shortly after it was proved: a refresh token left on a shared PC must not be enough to register an attacker's
 * questions or authenticator (and from then on reset this user's password).
 * @returns {boolean} false when the response has already been sent
 */
function freshEnough(req, res, dbUser) {
    if (dbUser.is_enrolled) return true; // factor changes on enrolled accounts ask for the password anyway
    if (Date.now() / 1000 - (req.user.authTime || 0) <= RECENT_AUTH_SECONDS) return true;
    res.status(401).json({
        success: false,
        code: 'RECENT_AUTH_REQUIRED',
        message: 'Please confirm your Windows password to continue setting up.',
    });
    return false;
}

// Security alert mail, never awaited: the change has been made already
function alertUser(req, change) {
    notificationService.sendSecurityChangeAlert({ userId: req.user.userId, username: req.user.username, change, req });
}

/**
 * Decide whether a factor change has to prove password knowledge, and do it.
 *
 * The rule is about the account, not the factor: once a user is enrolled they can reset their AD password
 * with the factors they hold, so *adding* a second one is as sensitive as replacing the one they have. A
 * stolen session could otherwise bind an attacker-controlled authenticator or phone to an enrolled account
 * and, from then on, reset that user's domain password from anywhere without ever knowing the old one.
 * Checking only "is this same factor already set" missed exactly that case (security review 2026-10-29).
 *
 * First-time enrolment stays password-free: an account that is not enrolled yet cannot reset anything,
 * so there is no capability to hijack, and the wizard would otherwise ask for the password twice.
 *
 * @param {object} dbUser - users row holding at least is_enrolled and the factor's own flag
 * @param {'totp'|'sms'} method - audited on failure, and names the factor's own flag
 * @returns {Promise<boolean>} false when the response has already been sent
 */
async function confirmFactorChange(req, res, dbUser, method) {
    const alreadySet = method === 'sms' ? dbUser.sms_enabled : dbUser.totp_enabled;
    if (!dbUser.is_enrolled && !alreadySet) return true;
    return confirmCurrentPassword(req, res, method);
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
        console.error('[Enrollment] Get questions error:', err.message);
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
        console.error('[Enrollment] Get my questions error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to load your security questions.' });
    }
}

/**
 * POST /api/enrollment/security-questions
 * Submit the configured number of selected security questions with answers.
 * Users enrolled under an older, larger count keep their extra answers until they save here again.
 * Body: { answers: [{ questionId: 1, answer: "..." }, ...] }
 */
async function submitSecurityQuestions(req, res) {
    const client = await db.getClient();

    try {
        const { answers } = req.body;

        const required = settingsService.current().security.questionCount;

        if (!answers || !Array.isArray(answers) || answers.length !== required) {
            return res.status(400).json({
                success: false,
                message: `Exactly ${required} security questions with answers are required.`,
            });
        }

        // Validate all questions exist and answers are non-empty
        const questionIds = answers.map(a => a.questionId);
        const uniqueIds = new Set(questionIds);
        if (uniqueIds.size !== required) {
            return res.status(400).json({
                success: false,
                message: `Please select ${required} different questions.`,
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

        if (existingHashes.size > 0) {
            if (!(await confirmCurrentPassword(req, res, 'security_questions'))) return;
        } else {
            const enrolledRow = await db.query('SELECT is_enrolled FROM users WHERE id = $1', [req.user.userId]);
            if (!freshEnough(req, res, enrolledRow.rows[0] || {})) return;
        }

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

        if (questionCheck.rows.length !== required) {
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
        if (existingHashes.size > 0) alertUser(req, 'Your security questions were changed');

        res.json({
            success: true,
            message: 'Security questions saved successfully.',
        });
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('[Enrollment] Submit security questions error:', err.message);
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
        if (!settingsService.current().factors.totp) {
            return res.status(400).json({
                success: false,
                code: 'FACTOR_DISABLED',
                message: 'Authenticator apps are not available. Please use the other verification method.',
            });
        }

        const current = await db.query('SELECT is_enrolled, totp_enabled FROM users WHERE id = $1', [req.user.userId]);
        if (!freshEnough(req, res, current.rows[0] || {})) return;
        if (!(await confirmFactorChange(req, res, current.rows[0] || {}, 'totp'))) return;

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
        console.error('[Enrollment] TOTP setup error:', err.message);
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

        if (typeof code !== 'string' || code.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Please enter a valid 6-digit code.',
            });
        }

        // Get the stored (encrypted) secret
        const result = await db.query(
            'SELECT totp_pending_secret, totp_enabled, is_enrolled FROM users WHERE id = $1',
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
            await logAudit(req.user.userId, req.user.username, 'enrollment', 'totp', req, false, 'Invalid code');
            return res.status(400).json({
                success: false,
                message: 'Invalid code. Please try again with a fresh code from your authenticator app.',
            });
        }

        // Enable TOTP
        let enrolledNow = false;
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
            enrolledNow = await updateEnrollmentStatus(client, req.user.userId);
            await client.query('COMMIT');
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }

        await logAudit(req.user.userId, req.user.username, wasEnabled ? 'totp_replaced' : 'enrollment', 'totp', req, true);
        if (!result.rows[0].is_enrolled && enrolledNow) {
            alertUser(req, 'Your account was enrolled for self-service password reset');
        } else {
            alertUser(req, wasEnabled ? 'Your authenticator app was replaced' : 'An authenticator app was added');
        }

        res.json({
            success: true,
            message: wasEnabled
                ? 'New authenticator verified. Your previous device no longer works.'
                : 'Authenticator app verified and enabled successfully.',
        });
    } catch (err) {
        console.error('[Enrollment] TOTP verify error:', err.message);
        res.status(500).json({
            success: false,
            message: 'Failed to verify TOTP code.',
        });
    }
}

/**
 * POST /api/enrollment/sms/setup
 * Send a one-time code to the user's mobile number so it can be verified.
 * Body: { mobile?, currentPassword? }
 *   mobile          required only when Active Directory holds no number for the account
 *   currentPassword required when SMS is already enabled (same rule as replacing an authenticator)
 */
async function setupSMS(req, res) {
    try {
        if (!settingsService.current().factors.sms) {
            return res.status(400).json({
                success: false,
                code: 'FACTOR_DISABLED',
                message: 'SMS codes are not available. Please use the other verification method.',
            });
        }

        const result = await db.query(
            'SELECT is_enrolled, sms_enabled, mobile_number, mobile_source, mobile_verified_hash FROM users WHERE id = $1',
            [req.user.userId]
        );
        const dbUser = result.rows[0] || {};

        const supplied = typeof req.body?.mobile === 'string' ? req.body.mobile.trim() : '';
        if (!freshEnough(req, res, dbUser)) return;
        if (!(await confirmFactorChange(req, res, dbUser, 'sms'))) return;

        let target;
        if (supplied) {
            const number = mobileService.normalize(supplied);
            if (!number) {
                return res.status(400).json({
                    success: false,
                    code: 'MOBILE_INVALID',
                    message: 'Enter a valid mobile number, including the country code (for example +919876543210).',
                });
            }
            target = { number, source: 'portal' };
        } else {
            const adUser = await ldapService.findUser(req.user.username);
            const resolved = mobileService.resolve(dbUser, adUser);
            // The directory number changed since it was verified: setting up again is how the user confirms it
            target = resolved?.changed ? { number: mobileService.normalize(adUser.mobile), source: 'ad' } : resolved;
            if (!target?.number) {
                return res.status(400).json({
                    success: false,
                    code: 'MOBILE_REQUIRED',
                    message: 'We do not have a mobile number for your account. Please enter the number to send codes to.',
                });
            }
        }

        const masked = mobileService.mask(target.number);

        // Staged like a pending authenticator secret: the number only becomes the user's once a code sent to
        // it has been entered, so a typo cannot point future codes at someone else's phone. Kept (encrypted) for
        // directory numbers too, so verification can pin exactly the number that received the code.
        await db.query(
            'UPDATE users SET mobile_pending = $1, mobile_pending_source = $2, updated_at = NOW() WHERE id = $3',
            [mobileService.encrypt(target.number), target.source, req.user.userId]
        );

        const { resendAfter, gateway, retriedAfter } = await smsOtpService.issue({
            userId: req.user.userId,
            purpose: 'enrollment',
            number: target.number,
            maskedNumber: masked,
        });

        // Audited on the way out, not only when it fails: an enrolment that goes quiet is the common
        // support call, and without this row there is nothing to show a code was ever sent.
        await logAudit(req.user.userId, req.user.username, 'enrollment_sms', 'sms', req, true,
            smsOtpService.sentDetail(masked, gateway, retriedAfter));

        res.json({
            success: true,
            data: {
                mobileMasked: masked,
                source: target.source,
                resendAfter,
                expiresInMinutes: smsOtpService.CODE_TTL_MINUTES,
                message: `We sent a 6-digit code to ${masked}.`,
            },
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
            return smsLimitResponse(err, { id: req.user.userId, username: req.user.username }, req, res);
        }
        console.error('[Enrollment] SMS setup error:', err.message);
        await logAudit(req.user.userId, req.user.username, 'enrollment_sms', 'sms', req, false, `Code not sent: ${err.message}`);
        if (smsService.isTemporaryFailure(err)) {
            // The provider is down or overloaded: say so, and point at the other factor when it is on offer
            const alternative = settingsService.current().factors?.totp
                ? ', or go back and set up an authenticator app instead'
                : '';
            return res.status(503).json({
                success: false,
                code: 'SMS_UNAVAILABLE',
                message: `The text message service is not responding right now, so no code was sent. Please try again in a few minutes${alternative}.`,
            });
        }
        res.status(502).json({
            success: false,
            message: 'We could not send the text message. Please try again, or contact your administrator.',
        });
    }
}

/**
 * POST /api/enrollment/sms/verify
 * Confirm the code sent by setupSMS and enable SMS as a second factor.
 * Body: { code }
 */
async function verifySMS(req, res) {
    try {
        const result = await db.query(
            'SELECT sms_enabled, is_enrolled, mobile_pending, mobile_pending_source FROM users WHERE id = $1',
            [req.user.userId]
        );
        const dbUser = result.rows[0];

        if (!dbUser || !dbUser.mobile_pending_source) {
            return res.status(400).json({
                success: false,
                message: 'No verification is in progress. Please request a new code.',
            });
        }

        const check = await smsOtpService.verify({ userId: req.user.userId, purpose: 'enrollment', code: req.body?.code });
        if (!check.ok) {
            await logAudit(req.user.userId, req.user.username, 'enrollment', 'sms', req, false, `Invalid code (${check.reason})`);
            return res.status(400).json({ success: false, message: smsOtpService.codeErrorMessage(check.reason) });
        }

        const wasEnabled = dbUser.sms_enabled;
        // The number the code went to; rows staged before pinning existed hold no pending directory number
        const pendingNumber = dbUser.mobile_pending ? cryptoService.decrypt(dbUser.mobile_pending) : null;
        const verifiedHash = pendingNumber ? cryptoService.hmac(pendingNumber) : check.numberHash;
        let enrolledNow = false;
        const client = await db.getClient();
        try {
            await client.query('BEGIN');
            // Only portal-supplied numbers are stored; a directory number is re-read from AD and checked
            // against mobile_verified_hash on every send
            await client.query(
                `UPDATE users SET mobile_number = CASE WHEN mobile_pending_source = 'portal' THEN mobile_pending ELSE NULL END,
                        mobile_source = mobile_pending_source, mobile_verified_hash = $2,
                        mobile_pending = NULL, mobile_pending_source = NULL, mobile_verified_at = NOW(),
                        sms_enabled = TRUE, updated_at = NOW()
                 WHERE id = $1`,
                [req.user.userId, verifiedHash]
            );
            enrolledNow = await updateEnrollmentStatus(client, req.user.userId);
            await client.query('COMMIT');
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }

        await logAudit(req.user.userId, req.user.username, wasEnabled ? 'sms_replaced' : 'enrollment', 'sms', req, true);
        const masked = pendingNumber ? mobileService.mask(pendingNumber) : 'your mobile';
        if (!dbUser.is_enrolled && enrolledNow) {
            alertUser(req, 'Your account was enrolled for self-service password reset');
        } else {
            alertUser(req, wasEnabled ? `Text-message codes now go to ${masked}` : `Text-message codes were set up for ${masked}`);
        }

        res.json({
            success: true,
            message: wasEnabled
                ? 'New mobile number verified. Codes now go to this number only.'
                : 'Mobile number verified. You can now reset your password with an SMS code.',
        });
    } catch (err) {
        console.error('[Enrollment] SMS verify error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to verify the code.' });
    }
}

/**
 * GET /api/enrollment/status
 * Check the user's enrollment completion status.
 */
async function getStatus(req, res) {
    try {
        const result = await db.query(
            `SELECT is_enrolled, totp_enabled, sms_enabled, security_questions_set,
                    mobile_number, mobile_source, mobile_verified_hash FROM users WHERE id = $1`,
            [req.user.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found.',
            });
        }

        const user = result.rows[0];
        const factors = settingsService.current().factors;
        // One lookup: the mobile number (when SMS is on) and whether reset is possible for this account at all
        const adUser = await ldapService.findUser(req.user.username).catch(() => null);
        const mobile = factors.sms ? mobileService.resolve(user, adUser) : null;

        res.json({
            success: true,
            data: {
                isEnrolled: user.is_enrolled,
                totpEnabled: user.totp_enabled,
                smsEnabled: user.sms_enabled,
                securityQuestionsSet: user.security_questions_set,
                // How many questions this user must set now; an older enrollment may still hold more
                questionCount: settingsService.current().security.questionCount,
                // Which second factors the administrator allows right now
                factors: { totp: factors.totp, sms: factors.sms },
                mobile: {
                    masked: mobile?.number ? mobileService.mask(mobile.number) : '',
                    source: mobile ? mobile.source : null,
                    // false = the portal has to ask the user for a number
                    inDirectory: Boolean(mobileService.normalize(adUser?.mobile)),
                    // The directory number is not the one verified: no codes until the user confirms it
                    changedInDirectory: Boolean(mobile?.changed),
                },
                // Protected (administrator) accounts can change but not reset their password here
                selfServiceReset: !resetBlockedForProtected(adUser, ldapService.serviceAccountPrivileged?.() ?? null),
                steps: {
                    securityQuestions: user.security_questions_set ? 'complete' : 'pending',
                    totp: user.totp_enabled ? 'complete' : 'pending',
                    sms: user.sms_enabled ? 'complete' : 'pending',
                },
            },
        });
    } catch (err) {
        console.error('[Enrollment] Status error:', err.message);
        res.status(500).json({
            success: false,
            message: 'Failed to check enrollment status.',
        });
    }
}

/**
 * Update the is_enrolled flag: security questions plus at least one enabled second factor.
 * @returns {Promise<boolean>} the new is_enrolled value
 */
async function updateEnrollmentStatus(client, userId) {
    const result = await client.query(
        'SELECT security_questions_set, totp_enabled, sms_enabled FROM users WHERE id = $1',
        [userId]
    );

    if (result.rows.length > 0) {
        const user = result.rows[0];
        const factors = settingsService.current().factors;
        // Security questions plus one second factor the administrator currently allows. With SMS off
        // (the default) this is the original "questions and authenticator" rule.
        const hasSecondFactor = (factors.totp && user.totp_enabled) || (factors.sms && user.sms_enabled);
        const isEnrolled = user.security_questions_set && hasSecondFactor;

        await client.query(
            'UPDATE users SET is_enrolled = $1, updated_at = NOW() WHERE id = $2',
            [isEnrolled, userId]
        );
        return Boolean(isEnrolled);
    }
    return false;
}

module.exports = {
    getQuestions,
    getMyQuestions,
    submitSecurityQuestions,
    setupTOTP,
    verifyTOTPSetup,
    setupSMS,
    verifySMS,
    getStatus,
};
