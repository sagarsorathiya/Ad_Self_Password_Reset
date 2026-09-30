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

// Words/phrases not allowed in new passwords
router.get('/password-exceptions', adminController.getPasswordExceptions);
router.post('/password-exceptions', adminController.addPasswordException);
router.put('/password-exceptions/:id', adminController.updatePasswordException);
router.delete('/password-exceptions/:id', adminController.deletePasswordException);

module.exports = router;
