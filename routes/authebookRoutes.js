const express = require('express');
const router = express.Router();
const authController = require('../controllers/authebookController');
const { requireAuth, isAuthenticated } = require('../middleware/auth');

// Auth routes
router.get('/login', authController.loginPage);
router.post('/login', authController.login);
router.post('/logout', authController.logout);

// Change credentials route
router.get('/change-credentials', requireAuth, authController.changeCredentialsPage);
router.post('/change-credentials', requireAuth, authController.changeCredentials);

// ✅ ADDED: Emergency reset route (remove in production)
router.get('/emergency-reset', authController.emergencyReset);

// User management routes (protected)
router.get('/api/users', isAuthenticated, authController.getUsers);
router.post('/api/users', isAuthenticated, authController.createUser);
router.delete('/api/users/:id', isAuthenticated, authController.deleteUser);

module.exports = router;