const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'admin'
    },
    lastLogin: {
        type: Date,
        default: Date.now
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// ✅ FIXED: Hash password before saving - Only when password is modified
userSchema.pre('save', async function(next) {
    // Only hash the password if it has been modified (or is new)
    if (!this.isModified('password')) return next();
    
    try {
        console.log('🔐 Hashing password for user:', this.username);
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        console.log('✅ Password hashed successfully');
        next();
    } catch (error) {
        console.error('❌ Password hashing error:', error);
        next(error);
    }
});

// ✅ FIXED: Compare password method with better error handling
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        if (!candidatePassword) {
            console.log('❌ No candidate password provided');
            return false;
        }
        
        console.log('🔐 Comparing passwords for user:', this.username);
        const isMatch = await bcrypt.compare(candidatePassword, this.password);
        console.log('✅ Password comparison result:', isMatch);
        return isMatch;
    } catch (error) {
        console.error('❌ Password comparison error:', error);
        return false;
    }
};

// ✅ ADDED: Update password method (for direct updates)
userSchema.methods.updatePassword = async function(newPassword) {
    try {
        console.log('🔄 Updating password for user:', this.username);
        this.password = newPassword;
        await this.save();
        console.log('✅ Password updated successfully');
        return true;
    } catch (error) {
        console.error('❌ Password update error:', error);
        return false;
    }
};

// ✅ ADDED: Update username method
userSchema.methods.updateUsername = async function(newUsername) {
    try {
        console.log('🔄 Updating username from', this.username, 'to', newUsername);
        this.username = newUsername;
        await this.save();
        console.log('✅ Username updated successfully');
        return true;
    } catch (error) {
        console.error('❌ Username update error:', error);
        return false;
    }
};

// ✅ FIXED: Static method to create default admin user
userSchema.statics.createDefaultAdmin = async function() {
    try {
        const adminExists = await this.findOne({ username: 'admin' });
        if (!adminExists) {
            await this.create({
                username: 'admin',
                password: 'admin123',
                role: 'admin'
            });
            console.log('✅ Default admin user created: admin / admin123');
        } else {
            console.log('ℹ️ Default admin user already exists');
        }
    } catch (error) {
        console.error('❌ Error creating default admin:', error);
    }
};

// ✅ ADDED: Find user by credentials method
userSchema.statics.findByCredentials = async function(username, password) {
    try {
        console.log('🔍 Finding user by credentials:', username);
        
        const user = await this.findOne({ 
            username: username.trim(),
            isActive: true 
        });
        
        if (!user) {
            console.log('❌ User not found:', username);
            return null;
        }
        
        console.log('✅ User found, comparing password...');
        const isPasswordValid = await user.comparePassword(password);
        
        if (isPasswordValid) {
            console.log('✅ Password valid for user:', username);
            return user;
        } else {
            console.log('❌ Password invalid for user:', username);
            return null;
        }
    } catch (error) {
        console.error('❌ Find by credentials error:', error);
        return null;
    }
};

// ✅ ADDED: Reset to default admin (for emergency cases)
userSchema.statics.resetToDefaultAdmin = async function() {
    try {
        // Delete all existing users
        await this.deleteMany({});
        
        // Create default admin
        await this.create({
            username: 'admin',
            password: 'admin123',
            role: 'admin'
        });
        
        console.log('✅ Reset to default admin: admin / admin123');
        return true;
    } catch (error) {
        console.error('❌ Reset to default admin error:', error);
        return false;
    }
};

module.exports = mongoose.model('Userebook', userSchema);