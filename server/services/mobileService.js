// The mobile number a one-time code is sent to.
//
// Where it comes from:
//   'ad'     the mobile attribute of the Active Directory account. Read again on every send, so a number
//            maintained by HR in the directory stays authoritative.
//   'portal' the user typed it in during enrolment because AD had none. Stored AES-256-GCM encrypted,
//            exactly like TOTP secrets; the portal never writes back to AD.
// A number the user verified in the portal wins over AD, so a later AD entry cannot silently redirect codes.
const crypto = require('crypto');
const config = require('../config/default');
const cryptoService = require('./cryptoService');
const settingsService = require('./settingsService');

const MIN_DIGITS = 8;
const MAX_DIGITS = 15; // E.164

// Dialling code for numbers typed without one; the admin panel value wins over .env
function countryCode() {
    return (settingsService.current().sms.countryCode || config.sms.countryCode).replace('+', '');
}

// Shortest subscriber number worth treating as already complete, after a dialling code
const MIN_SUBSCRIBER_DIGITS = 9;

/**
 * Normalize user or directory input to E.164 (+<country><subscriber>).
 * Accepts "98765 43210", "(+91) 98765-43210", "0098765...", "09876543210", "919876543210".
 * @param {string} raw
 * @returns {string|null} the normalized number, or null when it is not usable
 */
function normalize(raw) {
    let text = String(raw ?? '').trim();
    if (!text) return null;

    // Keep a leading + and digits only; "ext."/letters make the number unusable for SMS
    const plus = text.startsWith('+') || text.startsWith('00');
    text = text.replace(/^00/, '').replace(/[^\d]/g, '');
    if (!text) return null;

    let national = text;
    if (!plus) {
        const code = countryCode();
        if (!code) return null; // Without a dialling code a bare national number cannot be dialled
        // "919876543210" already carries the dialling code: prefixing it again would give +91919876543210.
        // A bare national number that happens to start with the same digits (e.g. 9187654321 in +91) is
        // still too short to be a complete international number, so it is prefixed as intended.
        const alreadyInternational = text.startsWith(code) && text.length >= code.length + MIN_SUBSCRIBER_DIGITS;
        national = alreadyInternational ? text : `${code}${text.replace(/^0+/, '')}`;
    }

    if (national.length < MIN_DIGITS || national.length > MAX_DIGITS) return null;
    return `+${national}`;
}

/**
 * Hide all but the last two digits: "+919876543210" -> "+91 •••••• 10".
 * Short enough to confirm the right phone, too little to identify the number.
 */
function mask(number) {
    const normalized = normalize(number);
    if (!normalized) return '';
    const digits = normalized.slice(1);
    const code = countryCode();
    const shown = code && digits.startsWith(code) ? code : '';
    const hidden = Math.max(2, digits.length - shown.length - 2);
    return `+${shown}${shown ? ' ' : ''}${'•'.repeat(hidden)} ${digits.slice(-2)}`;
}

/**
 * A stable, fake masked number for an account that does not exist or has no SMS factor, so the reset page
 * looks identical whether or not the username is real.
 */
function decoyMask(username) {
    const digest = crypto.createHmac('sha256', config.jwt.secret).update(`sms:${String(username).toLowerCase()}`).digest('hex');
    const last = String(parseInt(digest.slice(0, 4), 16) % 100).padStart(2, '0');
    const code = countryCode();
    return `+${code}${code ? ' ' : ''}${'•'.repeat(8)} ${last}`;
}

/**
 * The number codes should go to right now.
 * @param {object} dbUser - users row with mobile_source and mobile_number
 * @param {object|null} adUser - the AD entry, when it has already been fetched
 * @returns {{number: string, source: 'ad'|'portal'}|null}
 */
function resolve(dbUser, adUser) {
    if (dbUser?.mobile_source === 'portal' && dbUser.mobile_number) {
        const number = normalize(cryptoService.decrypt(dbUser.mobile_number));
        if (number) return { number, source: 'portal' };
    }
    const fromDirectory = normalize(adUser?.mobile);
    if (fromDirectory) return { number: fromDirectory, source: 'ad' };
    return null;
}

/** Encrypt a normalized number for storage (portal-supplied numbers only). */
function encrypt(number) {
    return cryptoService.encrypt(number);
}

module.exports = { normalize, mask, decoyMask, resolve, encrypt, MIN_DIGITS, MAX_DIGITS };
