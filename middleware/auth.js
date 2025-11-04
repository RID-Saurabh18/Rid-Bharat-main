const User = require('../models/EbookUser');

// Session-based authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session && req.session.user) {
        next();
    } else {
        res.redirect('/ebook/login?redirect=' + encodeURIComponent(req.originalUrl));
    }
};

// Check if user is authenticated (for API routes)
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.user) {
        next();
    } else {
        res.status(401).json({ 
            error: 'Authentication required',
            redirect: '/ebook/login'
        });
    }
};

// Admin role check
const requireAdmin = (req, res, next) => {
    if (req.session && req.session.user && req.session.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ 
            error: 'Admin access required' 
        });
    }
};

module.exports = {
    requireAuth,
    isAuthenticated,
    requireAdmin
};