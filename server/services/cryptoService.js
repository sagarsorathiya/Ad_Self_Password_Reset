const crypto = require('crypto');
const config = require('../config/default');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

/**
 * Get the encryption key buffer from the hex string in config.
 * Falls back to a derived key from JWT_SECRET if TOTP_ENCRYPTION_KEY is not set.
 */
function getKeyBuffer() {
    if (config.totp.encryptionKey && config.totp.encryptionKey.length >= 64) {
        return Buffer.from(config.totp.encryptionKey, 'hex');
    }
    // Fallback: derive a key from JWT_SECRET (not ideal for production)
    return crypto.scryptSync(config.jwt.secret, 'totp-encryption-salt', 32);
}

/**
 * Encrypt plaintext using AES-256-GCM.
 * @param {string} plaintext
 * @returns {string} - Format: iv:authTag:ciphertext (all hex encoded)
 */
function encrypt(plaintext) {
    const key = getKeyBuffer();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt ciphertext encrypted with AES-256-GCM.
 * @param {string} encryptedText - Format: iv:authTag:ciphertext (all hex encoded)
 * @returns {string} - Decrypted plaintext
 */
function decrypt(encryptedText) {
    const key = getKeyBuffer();
    const parts = encryptedText.split(':');

    if (parts.length !== 3) {
        throw new Error('Invalid encrypted text format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const ciphertext = parts[2];

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

/**
 * Generate a cryptographically secure random hex string.
 * @param {number} bytes - Number of random bytes
 * @returns {string}
 */
function randomHex(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

module.exports = { encrypt, decrypt, randomHex };
