const mongoose = require('mongoose');

const pdfSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200
    },
    description: {
        type: String,
        trim: true,
        maxlength: 1000
    },
    filename: {
        type: String,
        required: true
    },
    originalFilename: {
        type: String,
        default: 'unknown.pdf'
    },
    coverImage: {
        type: String,
        default: null
    },
    rating: {
        type: Number,
        min: 1,
        max: 5,
        default: 4.0
    },
    category: {
        type: String,
        enum: ['technical', 'non-technical', 'other'],
        default: 'technical'
    },
    tags: [{
        type: String,
        trim: true
    }],
    fileSize: {
        type: Number,
        default: 0
    },
    viewCount: {
        type: Number,
        default: 0
    },
    downloadCount: {
        type: Number,
        default: 0
    },
    uploadDate: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Instance methods
pdfSchema.methods.incrementViewCount = async function() {
    this.viewCount += 1;
    return this.save();
};

pdfSchema.methods.incrementDownloadCount = async function() {
    this.downloadCount += 1;
    return this.save();
};

// Static methods
pdfSchema.statics.getCategoryStats = function() {
    return this.aggregate([
        {
            $group: {
                _id: '$category',
                count: { $sum: 1 },
                avgRating: { $avg: '$rating' },
                totalViews: { $sum: '$viewCount' },
                totalDownloads: { $sum: '$downloadCount' }
            }
        }
    ]);
};

module.exports = mongoose.model('PDF', pdfSchema);