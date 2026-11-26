const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate, requireActiveSession } = require('../middleware/auth');
const { loginLimiter, verifyLimiter } = require('../middleware/rateLimiter');

// POST /api/auth/login
router.post('/login', loginLimiter, authController.login);

// POST /api/auth/refresh
router.post('/refresh', authController.refresh);

// GET /api/auth/me
router.get('/me', authenticate, requireActiveSession, authController.me);

// GET /api/auth/account-status  (dashboard: password expiry, reset policy, enabled factors)
router.get('/account-status', authenticate, requireActiveSession, authController.accountStatus);

// GET /api/auth/sign-in-info  (public: domain shown before the username field)
router.get('/sign-in-info', authController.signInInfo);

// POST /api/auth/reauth (confirm the password again; gives a fresh sign-in time for first enrolment)
router.post('/reauth', authenticate, requireActiveSession, verifyLimiter, authController.reauth);

// POST /api/auth/logout (no session check: a revoked session must still be able to sign out)
router.post('/logout', authenticate, authController.logout);

module.exports = router;
