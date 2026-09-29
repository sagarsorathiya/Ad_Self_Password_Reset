const express = require('express');
const router = express.Router();
const passwordController = require('../controllers/passwordController');
const { authenticate } = require('../middleware/auth');
const { resetLimiter, verifyLimiter } = require('../middleware/rateLimiter');

// Authenticated password change
router.post('/change', authenticate, passwordController.changePassword);

// Forgot password flow (unauthenticated)
router.post('/reset/verify-user', resetLimiter, passwordController.verifyUser);
router.post('/reset/get-questions', resetLimiter, passwordController.getUserQuestions);
router.post('/reset/verify-questions', verifyLimiter, passwordController.verifySecurityQuestions);
router.post('/reset/verify-totp', verifyLimiter, passwordController.verifyTOTP);
router.post('/reset/set-password', verifyLimiter, passwordController.setPassword);

module.exports = router;
