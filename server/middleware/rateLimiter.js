const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

function keyFor(req, scope) {
    const username = String(req.body?.username || req.user?.username || 'unknown').toLowerCase().slice(0, 256);
    return `${ipKeyGenerator(req.ip)}-${scope}-${username}`;
}
const config = require('../config/default');

/**
 * General API rate limiter.
 * Applied to all API routes.
 */
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: config.rateLimit.generalMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many requests. Please try again later.',
    },
});

/**
 * Strict rate limiter for login attempts.
 */
const loginLimiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => keyFor(req, 'login'),
    message: {
        success: false,
        message: 'Too many login attempts. Please try again in 15 minutes.',
    },
});

/**
 * Strict rate limiter for password reset attempts.
 */
const resetLimiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => keyFor(req, 'reset'),
    message: {
        success: false,
        message: 'Too many reset attempts. Please try again in 15 minutes.',
    },
});

/**
 * Strict rate limiter for verification (security questions, TOTP).
 */
const verifyLimiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => keyFor(req, 'verify'),
    message: {
        success: false,
        message: 'Too many verification attempts. Please try again in 15 minutes.',
    },
});

module.exports = {
    generalLimiter,
    loginLimiter,
    resetLimiter,
    verifyLimiter,
};
