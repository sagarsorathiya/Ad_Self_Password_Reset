const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { authenticate } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');

// All admin routes require authentication + admin role
router.use(authenticate, requireAdmin);

// Users management
router.get('/users', adminController.getUsers);
router.put('/users/:id/lock', adminController.toggleLock);
router.put('/users/:id/reset-enrollment', adminController.resetEnrollment);

// Statistics
router.get('/stats', adminController.getStats);

// Audit log
router.get('/audit-log', adminController.getAuditLog);

// Security questions management
router.get('/questions', adminController.getQuestions);
router.post('/questions', adminController.addQuestion);
router.put('/questions/:id', adminController.updateQuestion);

module.exports = router;
