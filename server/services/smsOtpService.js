// One-time codes delivered by SMS, for enrolment ("is this really your phone?") and for password reset.
//
// Rules, all enforced here so both callers behave the same:
//   - 6 random digits from crypto.randomInt, stored only as a bcrypt hash
//   - valid for CODE_TTL_MINUTES, and only the newest code per (user, purpose) is accepted
//   - at most MAX_ATTEMPTS guesses, then the code is dead and a new one must be requested
//   - a new code cannot be requested within RESEND_COOLDOWN_SECONDS (an SMS costs money and reaches a phone)
//   - single use: the row is consumed in one UPDATE, so two parallel requests cannot both succeed
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../config/db');
const smsService = require('./smsService');

const CODE_LENGTH = 6;
const CODE_TTL_MINUTES = 10;
const MAX_ATTEMPTS = 5;
const RESEND_COOLDOWN_SECONDS = 60;
// Lower than the cost used for security answers: a 6-digit code lives 10 minutes and allows 5 guesses,
// and verification happens while the user waits.
const BCRYPT_ROUNDS = 10;

class CooldownError extends Error {
    constructor(retryAfter) {
        super(`Please wait ${retryAfter} seconds before requesting another code.`);
        this.name = 'CooldownError';
        this.retryAfter = retryAfter;
    }
}

function generateCode() {
    return String(crypto.randomInt(0, 10 ** CODE_LENGTH)).padStart(CODE_LENGTH, '0');
}

/**
 * Seconds left before another code may be sent, 0 when one may be sent now.
 */
async function cooldownRemaining(userId, purpose) {
    const result = await db.query(
        `SELECT EXTRACT(EPOCH FROM (NOW() - created_at)) AS age FROM sms_codes
         WHERE user_id = $1 AND purpose = $2 ORDER BY created_at DESC LIMIT 1`,
        [userId, purpose]
    );
    if (result.rows.length === 0) return 0;
    return Math.max(0, Math.ceil(RESEND_COOLDOWN_SECONDS - Number(result.rows[0].age)));
}

/**
 * Send a fresh code and invalidate any earlier one.
 * @param {object} p - { userId, purpose: 'enrollment'|'reset', number: E.164, maskedNumber }
 * @returns {Promise<{expiresAt: Date, resendAfter: number}>}
 * @throws {CooldownError} when the previous code is too recent
 */
async function issue({ userId, purpose, number, maskedNumber }) {
    const wait = await cooldownRemaining(userId, purpose);
    if (wait > 0) throw new CooldownError(wait);

    const code = generateCode();
    const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000);

    // Earlier codes stop working the moment a new one is issued
    await db.query('DELETE FROM sms_codes WHERE user_id = $1 AND purpose = $2', [userId, purpose]);
    const inserted = await db.query(
        `INSERT INTO sms_codes (user_id, purpose, code_hash, mobile_hint, expires_at)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [userId, purpose, await bcrypt.hash(code, BCRYPT_ROUNDS), maskedNumber || null, expiresAt]
    );

    try {
        await smsService.send({ to: number, text: smsService.buildMessage(code, CODE_TTL_MINUTES) });
    } catch (err) {
        // Released like a reminder that failed to send: a code the user never received must not sit in the
        // way of the next attempt, neither as the "newest code" nor as a cooldown
        await db.query('DELETE FROM sms_codes WHERE id = $1', [inserted.rows[0].id]);
        throw err;
    }

    return { expiresAt, resendAfter: RESEND_COOLDOWN_SECONDS };
}

/**
 * Check a code the user typed and consume it on success.
 * @returns {Promise<{ok: true}|{ok: false, reason: 'none'|'expired'|'attempts'|'mismatch'}>}
 */
async function verify({ userId, purpose, code }) {
    if (!/^\d{6}$/.test(String(code || ''))) return { ok: false, reason: 'mismatch' };

    const result = await db.query(
        `SELECT id, code_hash, attempts, expires_at FROM sms_codes
         WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL
         ORDER BY created_at DESC LIMIT 1`,
        [userId, purpose]
    );
    if (result.rows.length === 0) return { ok: false, reason: 'none' };

    const row = result.rows[0];
    if (new Date(row.expires_at).getTime() < Date.now()) return { ok: false, reason: 'expired' };
    if (row.attempts >= MAX_ATTEMPTS) return { ok: false, reason: 'attempts' };

    if (!(await bcrypt.compare(String(code), row.code_hash))) {
        await db.query('UPDATE sms_codes SET attempts = attempts + 1 WHERE id = $1', [row.id]);
        const left = MAX_ATTEMPTS - (row.attempts + 1);
        return { ok: false, reason: left > 0 ? 'mismatch' : 'attempts' };
    }

    // Consumed in one statement: a code replayed from a second tab finds no unconsumed row
    const consumed = await db.query(
        'UPDATE sms_codes SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL RETURNING id',
        [row.id]
    );
    return consumed.rows.length === 1 ? { ok: true } : { ok: false, reason: 'none' };
}

/**
 * What to tell the user about a rejected code. Says enough to act on ("ask for a new one") without
 * confirming to a stranger that the account or an outstanding code exists.
 */
function codeErrorMessage(reason) {
    return {
        none: 'That code is no longer valid. Please request a new one.',
        expired: 'That code has expired. Please request a new one.',
        attempts: 'Too many incorrect codes. Please request a new one.',
    }[reason] || 'Incorrect code. Please check the message and try again.';
}

/** Drop every outstanding code for a user, e.g. after an admin resets their enrolment. */
async function clear(userId) {
    await db.query('DELETE FROM sms_codes WHERE user_id = $1', [userId]);
}

/** Housekeeping alongside the reset-token cleanup. */
async function purgeExpired() {
    const result = await db.query("DELETE FROM sms_codes WHERE expires_at < NOW() - INTERVAL '1 day'");
    return result.rowCount;
}

module.exports = {
    issue,
    verify,
    codeErrorMessage,
    clear,
    purgeExpired,
    cooldownRemaining,
    CooldownError,
    CODE_TTL_MINUTES,
    MAX_ATTEMPTS,
    RESEND_COOLDOWN_SECONDS,
};
