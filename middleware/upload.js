const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ✅ FIXED: Ensure upload directories exist with correct paths
const ensureDirectories = () => {
    const pdfDir = path.join(process.cwd(), 'public', 'uploads', 'pdfs');
    const coverDir = path.join(process.cwd(), 'public', 'uploads', 'covers');
    
    if (!fs.existsSync(pdfDir)) {
        fs.mkdirSync(pdfDir, { recursive: true });
        console.log('✅ Created PDF directory:', pdfDir);
    }
    if (!fs.existsSync(coverDir)) {
        fs.mkdirSync(coverDir, { recursive: true });
        console.log('✅ Created covers directory:', coverDir);
    }
};

ensureDirectories();

// Configure multer storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const pdfDir = path.join(process.cwd(), 'public', 'uploads', 'pdfs');
        const coverDir = path.join(process.cwd(), 'public', 'uploads', 'covers');
        
        if (file.fieldname === 'pdf') {
            cb(null, pdfDir);
        } else {
            cb(null, coverDir);
        }
    },
    filename: (req, file, cb) => {
        // Generate unique filename with timestamp and original extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExtension = path.extname(file.originalname);
        const filename = uniqueSuffix + fileExtension;
        console.log('📁 Generated filename:', filename);
        cb(null, filename);
    }
});

// File filter
const fileFilter = (req, file, cb) => {
    if (file.fieldname === 'pdf') {
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only PDF files are allowed'), false);
        }
    } else if (file.fieldname === 'coverImage') {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    } else {
        cb(new Error('Unexpected field'), false);
    }
};

// Configure multer
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 50 * 1024 * 1024, // 50MB
        files: 2
    }
});

// Error handling middleware for multer
const handleUploadErrors = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).render('upload', {
                error: 'File too large. Maximum size is 50MB.',
                pdfs: [],
                basePath: '/ebook'
            });
        }
        if (err.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).render('upload', {
                error: 'Too many files. Maximum 2 files allowed.',
                pdfs: [],
                basePath: '/ebook'
            });
        }
    } else if (err) {
        return res.status(400).render('upload', {
            error: err.message,
            pdfs: [],
            basePath: '/ebook'
        });
    }
    next();
};

module.exports = { upload, handleUploadErrors };