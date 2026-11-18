const express = require('express');
const router = express.Router();
const passwordController = require('../controllers/passwordController');
const { authenticate, requireActiveSession } = require('../middleware/auth');
const { resetLimiter, verifyLimiter, smsLimiter } = require('../middleware/rateLimiter');

// Authenticated password change
// verifyLimiter: every wrong current password is a bad-password count in AD
router.post('/change', authenticate, requireActiveSession, verifyLimiter, passwordController.changePassword);

// Password rules shown on the change and reset pages (no sign-in needed)
router.get('/rules', passwordController.getRules);

// Forgot password flow (unauthenticated)
router.post('/reset/verify-user', resetLimiter, passwordController.verifyUser);
router.post('/reset/get-questions', resetLimiter, passwordController.getUserQuestions);
router.post('/reset/verify-questions', verifyLimiter, passwordController.verifySecurityQuestions);
router.post('/reset/verify-totp', verifyLimiter, passwordController.verifyTOTP);
router.post('/reset/send-sms', smsLimiter, passwordController.sendResetSMS);
router.post('/reset/verify-sms', verifyLimiter, passwordController.verifySMS);
router.post('/reset/set-password', verifyLimiter, passwordController.setPassword);

module.exports = router;
