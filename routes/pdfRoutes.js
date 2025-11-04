const express = require('express');
const router = express.Router();
const pdfController = require('../controllers/pdfController');
const { upload, handleUploadErrors } = require('../middleware/upload');
const { requireAuth } = require('../middleware/auth');

// ==================== HEALTH & SECURITY ROUTES ====================
router.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        service: 'Book Library API',
        security: 'Protected Mode Active',
        authentication: req.session.user ? 'Authenticated' : 'Public'
    });
});

// ==================== DASHBOARD & PAGE ROUTES ====================
router.get('/', pdfController.dashboard);
router.get('/upload', requireAuth, pdfController.uploadForm);
router.get('/edit/:id', requireAuth, pdfController.editForm);

// ==================== PDF OPERATION ROUTES ====================
// Upload
router.post('/upload', 
    requireAuth,
    upload.fields([
        { name: 'pdf', maxCount: 1 },
        { name: 'coverImage', maxCount: 1 }
    ]),
    handleUploadErrors,
    pdfController.uploadPDF
);

// Edit
router.post('/edit/:id',
    requireAuth,
    upload.fields([
        { name: 'pdf', maxCount: 1 },
        { name: 'coverImage', maxCount: 1 }
    ]),
    handleUploadErrors,
    pdfController.editPDF
);

// Delete
router.post('/delete/:id', requireAuth, pdfController.deletePDF);

// ==================== VIEW & DOWNLOAD ROUTES ====================
router.get('/viewer/:id', pdfController.viewPDF);
router.get('/download/:id', pdfController.downloadPDF);
router.get('/secure-viewer/:id', pdfController.secureViewPDF);

// ==================== API ROUTES ====================
router.get('/api/stats', pdfController.getStats);
router.get('/api/stream-pdf', pdfController.streamPDF);

// ==================== SECURITY ROUTES ====================
router.post('/api/security/log', pdfController.logSecurityEvent);
router.get('/api/security/events', pdfController.getSecurityEvents);
router.post('/api/security/block-print', pdfController.blockPrintAttempt);
router.get('/api/security/health', pdfController.securityHealth);

module.exports = router;