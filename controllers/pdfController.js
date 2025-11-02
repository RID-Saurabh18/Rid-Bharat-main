const PDF = require('../models/PDF');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// ✅ Regular fs module import for createReadStream
const fsRegular = require('fs');

// Security event logging
const logSecurityEvent = (eventType, pdfId, req, details = {}) => {
    const event = {
        type: eventType,
        pdfId,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        details
    };
    
    console.log(`🛡️ Security Event: ${eventType}`, event);
    
    // Store in app security events
    if (req.app.locals.securityEvents) {
        req.app.locals.securityEvents.set(Date.now().toString(), event);
    }
};

// Helper function for safe file operations
const safeDeleteFile = async (filePath) => {
    try {
        await fs.access(filePath);
        await fs.unlink(filePath);
        console.log(`✅ Deleted file: ${filePath}`);
        return true;
    } catch (error) {
        if (error.code !== 'ENOENT') {
            console.error(`❌ Error deleting file ${filePath}:`, error);
        }
        return false;
    }
};

// ✅ Dashboard with basePath
exports.dashboard = async (req, res) => {
    try {
        const { search, filter = 'all', sort = 'newest', page = 1 } = req.query;
        const limit = 12;
        const skip = (parseInt(page) - 1) * limit;

        // Build query
        let query = {};
        if (search && search.trim() !== '') {
            query.$or = [
                { title: { $regex: search.trim(), $options: 'i' } },
                { description: { $regex: search.trim(), $options: 'i' } },
                { tags: { $regex: search.trim(), $options: 'i' } }
            ];
        }
        
        // ✅ FIXED: Use filter parameter for category filtering
        if (filter && filter !== 'all') {
            query.category = filter;
        }

        // Sort options
        const sortOptions = {
            'newest': { uploadDate: -1 },
            'oldest': { uploadDate: 1 },
            'rating': { rating: -1 },
            'title': { title: 1 },
            'views': { viewCount: -1 },
            'downloads': { downloadCount: -1 }
        };

        const [pdfs, total, stats, categories] = await Promise.all([
            PDF.find(query)
                .sort(sortOptions[sort] || sortOptions.newest)
                .skip(skip)
                .limit(limit)
                .lean(),
            PDF.countDocuments(query),
            PDF.aggregate([
                {
                    $group: {
                        _id: null,
                        totalBooks: { $sum: 1 },
                        avgRating: { $avg: '$rating' },
                        totalViews: { $sum: '$viewCount' },
                        totalDownloads: { $sum: '$downloadCount' },
                        totalSize: { $sum: '$fileSize' }
                    }
                }
            ]),
            PDF.distinct('category')
        ]);

        const totalPages = Math.ceil(total / limit);
        const currentPage = parseInt(page);

        res.render('dashboard', {
            pdfs,
            searchQuery: search || '',
            currentFilter: filter,
            sort,
            currentPage,
            totalPages,
            hasNextPage: currentPage < totalPages,
            hasPrevPage: currentPage > 1,
            categories,
            counts: {
                all: await PDF.countDocuments(),
                technical: await PDF.countDocuments({ category: 'technical' }),
                nonTechnical: await PDF.countDocuments({ category: 'non-technical' }),
                other: await PDF.countDocuments({ category: 'other' })
            },
            stats: stats[0] || { 
                totalBooks: 0, 
                avgRating: 0, 
                totalViews: 0, 
                totalDownloads: 0,
                totalSize: 0
            },
            // ✅ ADDED: basePath for /ebook routing
            basePath: '/ebook'
        });
    } catch (error) {
        console.error('Dashboard Error:', error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'Unable to load dashboard. Please try again later.',
            basePath: '/ebook'
        });
    }
};

// ✅ Upload Form with basePath
exports.uploadForm = async (req, res) => {
    try {
        const pdfs = await PDF.find().sort({ uploadDate: -1 }).limit(20);
        res.render('upload', { 
            pdfs,
            success: req.query.success,
            error: req.query.error,
            // ✅ ADDED: basePath for /ebook routing
            basePath: '/ebook'
        });
    } catch (error) {
        console.error('Upload Form Error:', error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'Unable to load upload form. Please try again later.',
            basePath: '/ebook'
        });
    }
};

// ✅ FIXED: Upload PDF with enhanced validation and file saving
exports.uploadPDF = async (req, res) => {
    try {
        if (!req.files?.pdf) {
            const pdfs = await PDF.find().sort({ uploadDate: -1 }).limit(20);
            return res.status(400).render('upload', {
                error: 'PDF file is required',
                pdfs,
                formData: req.body,
                basePath: '/ebook'
            });
        }

        const pdfFile = req.files.pdf[0];
        const coverFile = req.files.coverImage?.[0];

        // ✅ DEBUG: Log file information
        console.log('📄 PDF File Info:', {
            filename: pdfFile.filename,
            originalname: pdfFile.originalname,
            path: pdfFile.path,
            size: pdfFile.size,
            destination: pdfFile.destination
        });

        // ✅ VERIFY: File was actually moved to correct location
        const finalPdfPath = path.join(process.cwd(), 'public', 'uploads', 'pdfs', pdfFile.filename);
        console.log('📍 Final PDF Path:', finalPdfPath);

        // Check if file exists in final location
        try {
            await fs.access(finalPdfPath);
            console.log('✅ PDF file successfully saved to final location');
        } catch (error) {
            console.log('❌ PDF file NOT found in final location:', error.message);
            
            // Try to manually move the file
            try {
                await fs.copyFile(pdfFile.path, finalPdfPath);
                console.log('✅ Manually copied PDF file to final location');
            } catch (copyError) {
                console.log('❌ Failed to manually copy file:', copyError.message);
            }
        }

        // Validate file size
        if (pdfFile.size > 50 * 1024 * 1024) {
            await safeDeleteFile(pdfFile.path);
            if (coverFile) await safeDeleteFile(coverFile.path);
            
            const pdfs = await PDF.find().sort({ uploadDate: -1 }).limit(20);
            return res.status(400).render('upload', {
                error: 'PDF file must be less than 50MB',
                pdfs,
                formData: req.body,
                basePath: '/ebook'
            });
        }

        const newPDF = new PDF({
            title: req.body.title?.trim() || 'Untitled',
            description: req.body.description?.trim() || '',
            filename: pdfFile.filename,
            originalFilename: pdfFile.originalname,
            coverImage: coverFile?.filename || null,
            fileSize: pdfFile.size,
            rating: Math.min(5, Math.max(1, parseFloat(req.body.rating) || 4.0)),
            category: req.body.category || 'technical',
            tags: req.body.tags?.split(',').map(tag => tag.trim()).filter(tag => tag) || [],
            viewCount: 0,
            downloadCount: 0
        });

        await newPDF.save();
        
        // ✅ Verify file was actually saved to disk
        const savedPdfPath = path.join(process.cwd(), 'public/uploads/pdfs', pdfFile.filename);
        try {
            await fs.access(savedPdfPath);
            console.log('✅ PDF file successfully saved to:', savedPdfPath);
        } catch (error) {
            console.log('❌ PDF file was NOT saved to disk:', error.message);
        }

        if (coverFile) {
            const savedCoverPath = path.join(process.cwd(), 'public/uploads/covers', coverFile.filename);
            try {
                await fs.access(savedCoverPath);
                console.log('✅ Cover image successfully saved to:', savedCoverPath);
            } catch (error) {
                console.log('❌ Cover image was NOT saved to disk:', error.message);
            }
        }
        
        res.redirect('/ebook/upload?success=Book uploaded successfully');
    } catch (error) {
        console.error('Upload Error:', error);
        
        // Clean up uploaded files on error
        if (req.files?.pdf) await safeDeleteFile(req.files.pdf[0].path);
        if (req.files?.coverImage) await safeDeleteFile(req.files.coverImage[0].path);

        const pdfs = await PDF.find().sort({ uploadDate: -1 }).limit(20);
        res.status(500).render('upload', {
            error: 'Failed to upload book: ' + error.message,
            pdfs,
            formData: req.body,
            basePath: '/ebook'
        });
    }
};

// ✅ View PDF with basePath
exports.viewPDF = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).render('404', {
                title: 'Book Not Found',
                message: 'The requested book could not be found.',
                basePath: '/ebook'
            });
        }

        // Ensure required fields exist
        if (!pdf.originalFilename) {
            pdf.originalFilename = pdf.filename || 'unknown.pdf';
            await pdf.save();
        }

        // Increment view count
        pdf.viewCount = (pdf.viewCount || 0) + 1;
        await pdf.save();

        res.render('viewer', { 
            pdf,
            basePath: '/ebook'
        });
    } catch (error) {
        console.error('View PDF Error:', error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'Unable to load the book. Please try again.',
            basePath: '/ebook'
        });
    }
};

// ✅ FIXED: Enhanced Secure PDF viewer with basePath
exports.secureViewPDF = async (req, res) => {
    try {
        const pdfId = req.params.id;
        console.log('🔒 Secure view request for PDF ID:', pdfId);
        
        const pdf = await PDF.findById(pdfId);
        if (!pdf) {
            console.log('❌ PDF not found with ID:', pdfId);
            return res.status(404).render('404', {
                title: 'Book Not Found',
                message: 'The requested book could not be found.',
                basePath: '/ebook'
            });
        }

        console.log('✅ PDF found:', pdf.title);

        // Increment view count
        await PDF.findByIdAndUpdate(pdfId, { 
            $inc: { viewCount: 1 },
            $set: { lastAccessed: new Date() }
        });

        // Generate secure session token with enhanced security
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const tokenExpiry = Date.now() + (60 * 60 * 1000); // 1 hour
        
        // Initialize tokens map if it doesn't exist
        if (!req.app.locals.pdfTokens) {
            req.app.locals.pdfTokens = new Map();
        }
        
        // Store token with enhanced security data
        req.app.locals.pdfTokens.set(sessionToken, {
            pdfId: pdf._id.toString(),
            expires: tokenExpiry,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            createdAt: new Date().toISOString(),
            securityLevel: 'HIGH',
            features: ['PRINT_PROTECTION', 'DOWNLOAD_PROTECTION', 'SCREENSHOT_PROTECTION']
        });

        console.log('✅ Generated session token:', sessionToken.substring(0, 10) + '...');

        // Log security event
        logSecurityEvent('SECURE_VIEWER_ACCESSED', pdf._id.toString(), req, {
            securityFeatures: ['print_protection', 'download_protection', 'screenshot_protection']
        });

        res.render('viewer-secure', { 
            pdf,
            sessionToken,
            security: {
                disableDownload: true,
                disablePrint: true,
                disableTextSelect: true,
                disableScreenshot: true,
                enableWatermark: false,
                enablePrintMonitoring: true
            },
            // ✅ ADDED: basePath for /ebook routing
            basePath: '/ebook'
        });

    } catch (error) {
        console.error('❌ Secure View PDF Error:', error);
        res.status(500).render('error', {
            title: 'Security Error',
            message: 'Unable to load book in secure mode. Please try again.',
            basePath: '/ebook'
        });
    }
};

// ✅ FIXED: Enhanced Secure PDF streaming with CORRECT file path
exports.streamPDF = async (req, res) => {
    try {
        const { token } = req.query;
        console.log('📥 Stream PDF request received, token:', token ? 'present' : 'missing');
        
        // Verify session token
        if (!token) {
            console.log('❌ No token provided');
            logSecurityEvent('STREAM_ACCESS_DENIED', 'unknown', req, { reason: 'no_token' });
            return res.status(403).json({ error: 'No session token provided' });
        }

        const tokenData = req.app.locals.pdfTokens?.get(token);
        if (!tokenData) {
            console.log('❌ Invalid token:', token);
            logSecurityEvent('STREAM_ACCESS_DENIED', 'unknown', req, { reason: 'invalid_token' });
            return res.status(403).json({ error: 'Invalid session token' });
        }

        if (Date.now() > tokenData.expires) {
            console.log('❌ Token expired');
            req.app.locals.pdfTokens.delete(token);
            logSecurityEvent('STREAM_ACCESS_DENIED', tokenData.pdfId, req, { reason: 'token_expired' });
            return res.status(403).json({ error: 'Session token expired' });
        }

        const pdf = await PDF.findById(tokenData.pdfId);
        if (!pdf) {
            console.log('❌ PDF not found for ID:', tokenData.pdfId);
            return res.status(404).json({ error: 'PDF not found' });
        }

        // ✅ FIXED: CORRECT FILE PATH - Use absolute path
        const filePath = path.join(process.cwd(), 'public', 'uploads', 'pdfs', pdf.filename);
        console.log('🔍 Looking for PDF file:', filePath);
        
        // Check if file exists with better error handling
        try {
            await fs.access(filePath);
            console.log('✅ PDF file found, streaming...');
        } catch (error) {
            console.log('❌ PDF file not found:', error.message);
            console.log('📁 Available files in pdfs directory:');
            
            // List available files for debugging
            const pdfsDir = path.join(process.cwd(), 'public', 'uploads', 'pdfs');
            try {
                const files = await fs.readdir(pdfsDir);
                console.log('📄 Available PDF files:', files);
            } catch (dirError) {
                console.log('❌ Cannot read pdfs directory:', dirError.message);
            }
            
            return res.status(404).json({ 
                error: 'PDF file not found on server',
                details: `File ${pdf.filename} does not exist in uploads directory`
            });
        }

        // Enhanced security headers for print protection
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="protected-${pdf.title}.pdf"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
        res.setHeader('Referrer-Policy', 'no-referrer');
        
        // Enhanced caching prevention for print protection
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0, s-maxage=0');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');

        console.log('🚀 Streaming PDF with enhanced security headers');

        // ✅ FIXED: Use fsRegular (regular fs module) for createReadStream
        const fileStream = fsRegular.createReadStream(filePath);
        
        fileStream.on('error', (error) => {
            console.error('❌ File stream error:', error);
            logSecurityEvent('STREAM_ERROR', tokenData.pdfId, req, { error: error.message });
            if (!res.headersSent) {
                res.status(500).json({ error: 'Error streaming PDF file' });
            }
        });

        fileStream.on('open', () => {
            logSecurityEvent('PDF_STREAM_STARTED', tokenData.pdfId, req, {
                fileSize: pdf.fileSize,
                fileName: pdf.filename
            });
        });

        fileStream.pipe(res);

        // Log successful stream
        logSecurityEvent('PDF_STREAM_SUCCESS', tokenData.pdfId, req, {
            method: 'secure_stream',
            securityLevel: 'HIGH'
        });

    } catch (error) {
        console.error('❌ Stream PDF Error:', error);
        logSecurityEvent('STREAM_SERVER_ERROR', 'unknown', req, { error: error.message });
        if (!res.headersSent) {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
};

// ✅ Download PDF with basePath
exports.downloadPDF = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).render('404', {
                title: 'Book Not Found',
                message: 'The requested book could not be found.',
                basePath: '/ebook'
            });
        }

        // Enhanced download restriction
        const hasDownloadPermission = false; // Always false for security

        if (!hasDownloadPermission) {
            logSecurityEvent('DOWNLOAD_ATTEMPT_BLOCKED', pdf._id.toString(), req, {
                reason: 'download_disabled',
                message: 'Download feature is permanently disabled'
            });
            
            return res.status(403).render('error', {
                title: 'Download Disabled',
                message: 'Download access is permanently disabled for security reasons. Please use the secure viewer.',
                basePath: '/ebook'
            });
        }

        const filePath = path.join(process.cwd(), 'public', 'uploads', 'pdfs', pdf.filename);
        
        // Check if file exists
        try {
            await fs.access(filePath);
        } catch (error) {
            return res.status(404).render('error', {
                title: 'File Not Found',
                message: 'The PDF file could not be found on the server.',
                basePath: '/ebook'
            });
        }

        // Increment download count
        pdf.downloadCount = (pdf.downloadCount || 0) + 1;
        await pdf.save();

        // Set download headers
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${pdf.title}.pdf"`);
        
        // ✅ FIXED: Use fsRegular for download as well
        res.download(filePath, `${pdf.title}.pdf`);
        
        logSecurityEvent('DOWNLOAD_COMPLETED', pdf._id.toString(), req);

    } catch (error) {
        console.error('Download Error:', error);
        res.status(500).render('error', {
            title: 'Download Error',
            message: 'Unable to download the file. Please try again.',
            basePath: '/ebook'
        });
    }
};

// ✅ Edit Form with basePath
exports.editForm = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).render('404', {
                title: 'Book Not Found',
                message: 'The requested book could not be found.',
                basePath: '/ebook'
            });
        }

        res.render('edit', { 
            pdf,
            error: req.query.error,
            // ✅ ADDED: basePath for /ebook routing
            basePath: '/ebook'
        });
    } catch (error) {
        console.error('Edit Form Error:', error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'Unable to load edit form. Please try again later.',
            basePath: '/ebook'
        });
    }
};

// ✅ Update PDF with basePath
exports.editPDF = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).render('404', {
                title: 'Book Not Found',
                message: 'The requested book could not be found.',
                basePath: '/ebook'
            });
        }

        // Update basic fields
        pdf.title = req.body.title?.trim() || pdf.title;
        pdf.description = req.body.description?.trim() || pdf.description;
        pdf.rating = Math.min(5, Math.max(1, parseFloat(req.body.rating) || pdf.rating));
        pdf.category = req.body.category || pdf.category;
        pdf.tags = req.body.tags?.split(',').map(tag => tag.trim()).filter(tag => tag) || pdf.tags;

        // Handle PDF file replacement
        if (req.files?.pdf) {
            const oldPdfPath = path.join(process.cwd(), 'public', 'uploads', 'pdfs', pdf.filename);
            await safeDeleteFile(oldPdfPath);
            
            pdf.filename = req.files.pdf[0].filename;
            pdf.originalFilename = req.files.pdf[0].originalname;
            pdf.fileSize = req.files.pdf[0].size;
        }

        // Handle cover image replacement
        if (req.files?.coverImage) {
            if (pdf.coverImage) {
                const oldCoverPath = path.join(process.cwd(), 'public', 'uploads', 'covers', pdf.coverImage);
                await safeDeleteFile(oldCoverPath);
            }
            pdf.coverImage = req.files.coverImage[0].filename;
        }

        await pdf.save();
        res.redirect('/ebook/upload?success=Book updated successfully');
    } catch (error) {
        console.error('Edit PDF Error:', error);
        
        const pdf = await PDF.findById(req.params.id);
        res.status(500).render('edit', {
            pdf,
            error: 'Failed to update book: ' + error.message,
            basePath: '/ebook'
        });
    }
};

// ✅ Delete PDF with basePath
exports.deletePDF = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).render('404', {
                title: 'Book Not Found',
                message: 'The requested book could not be found.',
                basePath: '/ebook'
            });
        }

        // Delete associated files
        const pdfPath = path.join(process.cwd(), 'public', 'uploads', 'pdfs', pdf.filename);
        await safeDeleteFile(pdfPath);

        if (pdf.coverImage) {
            const coverPath = path.join(process.cwd(), 'public', 'uploads', 'covers', pdf.coverImage);
            await safeDeleteFile(coverPath);
        }

        await PDF.findByIdAndDelete(req.params.id);
        res.redirect('/ebook/upload?success=Book deleted successfully');
    } catch (error) {
        console.error('Delete PDF Error:', error);
        res.status(500).render('error', {
            title: 'Delete Error',
            message: 'Failed to delete book. Please try again.',
            basePath: '/ebook'
        });
    }
};

// Get book statistics (API)
exports.getStats = async (req, res) => {
    try {
        const stats = await PDF.aggregate([
            {
                $group: {
                    _id: null,
                    totalBooks: { $sum: 1 },
                    totalSize: { $sum: '$fileSize' },
                    avgRating: { $avg: '$rating' },
                    totalViews: { $sum: '$viewCount' },
                    totalDownloads: { $sum: '$downloadCount' },
                    categories: { 
                        $push: {
                            category: '$category',
                            count: 1
                        }
                    }
                }
            },
            {
                $project: {
                    totalBooks: 1,
                    totalSize: 1,
                    avgRating: { $round: ['$avgRating', 2] },
                    totalViews: 1,
                    totalDownloads: 1,
                    byCategory: {
                        $arrayToObject: {
                            $map: {
                                input: '$categories',
                                as: 'cat',
                                in: {
                                    k: '$$cat.category',
                                    v: '$$cat.count'
                                }
                            }
                        }
                    }
                }
            }
        ]);

        res.json(stats[0] || {
            totalBooks: 0,
            totalSize: 0,
            avgRating: 0,
            totalViews: 0,
            totalDownloads: 0,
            byCategory: {}
        });
    } catch (error) {
        console.error('Stats Error:', error);
        res.status(500).json({ 
            error: 'Unable to fetch statistics',
            details: error.message 
        });
    }
};

// Enhanced Security event logging endpoint
exports.logSecurityEvent = async (req, res) => {
    try {
        const { eventType, pdfId, details } = req.body;
        
        const securityEvent = {
            eventType,
            pdfId,
            details,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString(),
            severity: getEventSeverity(eventType)
        };

        console.log(`🔒 Client Security Event: ${eventType}`, securityEvent);

        // Store in security events
        if (req.app.locals.securityEvents) {
            req.app.locals.securityEvents.set(Date.now().toString(), securityEvent);
        }

        // Special handling for print attempts
        if (eventType.includes('PRINT')) {
            console.log(`🚨 PRINT ATTEMPT DETECTED: ${eventType}`, details);
        }

        res.json({ 
            status: 'logged', 
            eventId: Date.now().toString(),
            severity: securityEvent.severity
        });
    } catch (error) {
        console.error('Security log error:', error);
        res.status(500).json({ error: 'Logging failed' });
    }
};

// Get security events (admin endpoint)
exports.getSecurityEvents = async (req, res) => {
    try {
        const events = req.app.locals.securityEvents ? 
            Array.from(req.app.locals.securityEvents.entries())
                .map(([id, event]) => ({ id, ...event }))
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                .slice(0, 100) : [];

        // Filter for high severity events
        const highSeverityEvents = events.filter(event => event.severity === 'HIGH');
        
        res.json({
            totalEvents: events.length,
            highSeverityEvents: highSeverityEvents.length,
            recentEvents: events.slice(0, 20),
            printAttempts: events.filter(e => e.eventType.includes('PRINT')).length
        });
    } catch (error) {
        console.error('Get security events error:', error);
        res.status(500).json({ error: 'Failed to get security events' });
    }
};

// Print attempt blocking endpoint
exports.blockPrintAttempt = async (req, res) => {
    try {
        const { pdfId, reason, method } = req.body;
        
        const printEvent = {
            eventType: 'PRINT_ATTEMPT_BLOCKED',
            pdfId,
            details: {
                reason,
                method,
                blockedAt: new Date().toISOString(),
                action: 'automatically_blocked'
            },
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString(),
            severity: 'HIGH'
        };

        console.log(`🚨 PRINT ATTEMPT BLOCKED: ${method}`, printEvent);

        // Store the event
        if (req.app.locals.securityEvents) {
            req.app.locals.securityEvents.set(Date.now().toString(), printEvent);
        }

        res.json({ 
            status: 'blocked',
            message: 'Print attempt blocked successfully',
            eventId: Date.now().toString()
        });
    } catch (error) {
        console.error('Print block error:', error);
        res.status(500).json({ error: 'Failed to log print attempt' });
    }
};

// Security health check endpoint
exports.securityHealth = async (req, res) => {
    try {
        const health = {
            status: 'SECURE',
            timestamp: new Date().toISOString(),
            features: {
                printProtection: 'ACTIVE',
                downloadProtection: 'ACTIVE',
                screenshotProtection: 'ACTIVE',
                sessionManagement: 'ACTIVE'
            },
            stats: {
                activeSessions: req.app.locals.pdfTokens ? req.app.locals.pdfTokens.size : 0,
                securityEvents: req.app.locals.securityEvents ? req.app.locals.securityEvents.size : 0,
                blockedAttempts: req.app.locals.securityEvents ? 
                    Array.from(req.app.locals.securityEvents.values())
                        .filter(e => e.severity === 'HIGH').length : 0
            }
        };

        res.json(health);
    } catch (error) {
        console.error('Security health check error:', error);
        res.status(500).json({ 
            status: 'ERROR',
            error: 'Health check failed' 
        });
    }
};

// Helper function to determine event severity
function getEventSeverity(eventType) {
    const highSeverityEvents = [
        'PRINT_ATTEMPT',
        'SCREENSHOT_ATTEMPT', 
        'DOWNLOAD_ATTEMPT',
        'UNAUTHORIZED_ACCESS',
        'SECURITY_BREACH'
    ];
    
    const mediumSeverityEvents = [
        'CONTEXT_MENU_ATTEMPT',
        'KEYBOARD_SHORTCUT_BLOCKED',
        'DRAG_ATTEMPT'
    ];

    if (highSeverityEvents.some(e => eventType.includes(e))) {
        return 'HIGH';
    } else if (mediumSeverityEvents.some(e => eventType.includes(e))) {
        return 'MEDIUM';
    } else {
        return 'LOW';
    }
}

// ✅ Additional helper method: Get PDF by ID
exports.getPDFById = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).json({ error: 'PDF not found' });
        }
        res.json(pdf);
    } catch (error) {
        console.error('Get PDF by ID error:', error);
        res.status(500).json({ error: 'Failed to fetch PDF' });
    }
};

// ✅ Search PDFs API endpoint
exports.searchPDFs = async (req, res) => {
    try {
        const { q, category, page = 1, limit = 10 } = req.query;
        
        let query = {};
        
        // Search query
        if (q && q.trim() !== '') {
            query.$or = [
                { title: { $regex: q.trim(), $options: 'i' } },
                { description: { $regex: q.trim(), $options: 'i' } },
                { tags: { $regex: q.trim(), $options: 'i' } }
            ];
        }
        
        // Category filter
        if (category && category !== 'all') {
            query.category = category;
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        const [pdfs, total] = await Promise.all([
            PDF.find(query)
                .sort({ uploadDate: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .lean(),
            PDF.countDocuments(query)
        ]);

        res.json({
            pdfs,
            total,
            currentPage: parseInt(page),
            totalPages: Math.ceil(total / parseInt(limit)),
            hasNextPage: (parseInt(page) * parseInt(limit)) < total,
            hasPrevPage: parseInt(page) > 1
        });
    } catch (error) {
        console.error('Search PDFs error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
};

// ✅ Increment view count API
exports.incrementViewCount = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).json({ error: 'PDF not found' });
        }

        pdf.viewCount = (pdf.viewCount || 0) + 1;
        await pdf.save();

        res.json({ 
            success: true, 
            newViewCount: pdf.viewCount 
        });
    } catch (error) {
        console.error('Increment view count error:', error);
        res.status(500).json({ error: 'Failed to increment view count' });
    }
};

// ✅ Get PDF file info
exports.getPDFFileInfo = async (req, res) => {
    try {
        const pdf = await PDF.findById(req.params.id);
        if (!pdf) {
            return res.status(404).json({ error: 'PDF not found' });
        }

        const filePath = path.join(process.cwd(), 'public', 'uploads', 'pdfs', pdf.filename);
        
        try {
            const stats = await fs.stat(filePath);
            res.json({
                filename: pdf.filename,
                originalFilename: pdf.originalFilename,
                fileSize: pdf.fileSize,
                actualFileSize: stats.size,
                exists: true,
                uploadDate: pdf.uploadDate,
                lastModified: stats.mtime
            });
        } catch (error) {
            res.json({
                filename: pdf.filename,
                originalFilename: pdf.originalFilename,
                fileSize: pdf.fileSize,
                exists: false,
                error: 'File not found on disk'
            });
        }
    } catch (error) {
        console.error('Get PDF file info error:', error);
        res.status(500).json({ error: 'Failed to get file info' });
    }
};

// ✅ Clean up expired tokens (can be called periodically)
exports.cleanupExpiredTokens = async (req, res) => {
    try {
        const now = Date.now();
        let cleanedCount = 0;

        if (req.app.locals.pdfTokens) {
            for (const [token, tokenData] of req.app.locals.pdfTokens.entries()) {
                if (now > tokenData.expires) {
                    req.app.locals.pdfTokens.delete(token);
                    cleanedCount++;
                }
            }
        }

        res.json({
            status: 'success',
            cleanedCount,
            remainingTokens: req.app.locals.pdfTokens ? req.app.locals.pdfTokens.size : 0
        });
    } catch (error) {
        console.error('Cleanup tokens error:', error);
        res.status(500).json({ error: 'Cleanup failed' });
    }
};