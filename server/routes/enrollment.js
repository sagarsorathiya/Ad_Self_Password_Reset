const express = require('express');
const router = express.Router();
const enrollmentController = require('../controllers/enrollmentController');
const { authenticate } = require('../middleware/auth');
const { verifyLimiter } = require('../middleware/rateLimiter');

// All enrollment routes require authentication
router.use(authenticate);

// GET /api/enrollment/questions
router.get('/questions', enrollmentController.getQuestions);

// GET /api/enrollment/security-questions
router.get('/security-questions', enrollmentController.getMyQuestions);

// POST /api/enrollment/security-questions
router.post('/security-questions', verifyLimiter, enrollmentController.submitSecurityQuestions);

// POST /api/enrollment/totp/setup
router.post('/totp/setup', verifyLimiter, enrollmentController.setupTOTP);

// POST /api/enrollment/totp/verify
router.post('/totp/verify', verifyLimiter, enrollmentController.verifyTOTPSetup);

// GET /api/enrollment/status
router.get('/status', enrollmentController.getStatus);

module.exports = router;
