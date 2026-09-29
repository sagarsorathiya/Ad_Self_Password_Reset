const otplib = require('otplib');
const QRCode = require('qrcode');
const config = require('../config/default');
const cryptoService = require('./cryptoService');

// ±1 time step (30s) tolerance
const EPOCH_TOLERANCE_SECONDS = 30;

/**
 * Generate a new TOTP secret.
 * @returns {string} - Base32-encoded secret
 */
function generateSecret() {
    return otplib.generateSecret();
}

/**
 * Generate the otpauth:// URI for the authenticator app.
 * @param {string} secret - Base32-encoded secret
 * @param {string} username - User's sAMAccountName
 * @returns {string} - otpauth:// URI
 */
function generateKeyUri(secret, username) {
    return otplib.generateURI({ issuer: config.totp.issuer, label: username, secret });
}

/**
 * Generate a QR code as a data URL for the authenticator app.
 * @param {string} secret - Base32-encoded secret
 * @param {string} username - User's sAMAccountName
 * @returns {Promise<string>} - Data URL (base64 PNG)
 */
async function generateQRCode(secret, username) {
    const keyUri = generateKeyUri(secret, username);
    return QRCode.toDataURL(keyUri, {
        width: 256,
        margin: 2,
        color: {
            dark: '#000000',
            light: '#ffffff',
        },
    });
}

/**
 * Verify a TOTP token against a secret.
 * @param {string} token - 6-digit code from authenticator
 * @param {string} secret - Base32-encoded secret (plaintext)
 * @returns {boolean}
 */
function verifyToken(token, secret) {
    return verifyTokenStep(token, secret) !== null;
}

/**
 * Verify a TOTP token and return the matched time step, or null if invalid.
 */
function verifyTokenStep(token, secret) {
    try {
        if (!/^\d{6}$/.test(String(token))) return null;
        const result = otplib.verifySync({ secret, token: String(token), epochTolerance: EPOCH_TOLERANCE_SECONDS });
        return result.valid === true ? result.timeStep : null;
    } catch {
        return null;
    }
}

/**
 * Atomically record a used time step; false if this or a later step was already used.
 */
async function consumeStep(db, userId, step) {
    const result = await db.query(
        `UPDATE users SET totp_last_used_step = $1
         WHERE id = $2 AND (totp_last_used_step IS NULL OR totp_last_used_step < $1)
         RETURNING id`,
        [step, userId]
    );
    return result.rows.length === 1;
}

/**
 * Encrypt a TOTP secret for storage.
 * @param {string} secret - Plaintext base32-encoded secret
 * @returns {string} - Encrypted secret
 */
function encryptSecret(secret) {
    return cryptoService.encrypt(secret);
}

/**
 * Decrypt a stored TOTP secret.
 * @param {string} encryptedSecret - Encrypted secret from DB
 * @returns {string} - Plaintext base32-encoded secret
 */
function decryptSecret(encryptedSecret) {
    return cryptoService.decrypt(encryptedSecret);
}

module.exports = {
    generateSecret,
    generateKeyUri,
    generateQRCode,
    verifyToken,
    verifyTokenStep,
    consumeStep,
    encryptSecret,
    decryptSecret,
};
