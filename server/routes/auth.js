const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const { loginLimiter } = require('../middleware/rateLimiter');

// POST /api/auth/login
router.post('/login', loginLimiter, authController.login);

// POST /api/auth/refresh
router.post('/refresh', authController.refresh);

// GET /api/auth/me
router.get('/me', authenticate, authController.me);

// POST /api/auth/logout
router.post('/logout', authenticate, authController.logout);

module.exports = router;
