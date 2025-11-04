const User = require('../models/EbookUser');

// ✅ FIXED: Login page with basePath
exports.loginPage = (req, res) => {
    const { redirect } = req.query;
    res.render('login', { 
        title: 'Login',
        error: req.query.error,
        redirect: redirect || '/ebook/upload',
        success: req.query.success,
        basePath: '/ebook'
    });
};

// ✅ FIXED: Login handler with proper error handling
exports.login = async (req, res) => {
    try {
        const { username, password, redirect } = req.body;

        console.log('🔐 Login attempt for user:', username);

        if (!username || !password) {
            console.log('❌ Missing username or password');
            return res.redirect('/ebook/login?error=Username and password are required');
        }

        // Trim and validate input
        const trimmedUsername = username.trim();
        const trimmedPassword = password.trim();

        if (!trimmedUsername || !trimmedPassword) {
            console.log('❌ Empty username or password after trimming');
            return res.redirect('/ebook/login?error=Username and password are required');
        }

        // Find user using credentials method
        const user = await User.findByCredentials(trimmedUsername, trimmedPassword);
        
        if (!user) {
            console.log('❌ Login failed: Invalid credentials for user:', trimmedUsername);
            return res.redirect('/ebook/login?error=Invalid username or password');
        }

        // Create session
        req.session.user = {
            id: user._id.toString(),
            username: user.username,
            role: user.role
        };

        // Update last login
        await User.findByIdAndUpdate(user._id, { 
            lastLogin: new Date() 
        });

        console.log(`✅ User ${user.username} logged in successfully`);
        console.log('📋 Session created:', req.session.user);

        // Redirect to intended page or upload page
        const redirectUrl = redirect || '/ebook/upload';
        console.log('🔄 Redirecting to:', redirectUrl);
        res.redirect(redirectUrl);

    } catch (error) {
        console.error('❌ Login error:', error);
        res.redirect('/ebook/login?error=Login failed. Please try again.');
    }
};

// ✅ FIXED: Logout handler
exports.logout = (req, res) => {
    const username = req.session.user?.username;
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Logout error:', err);
            return res.redirect('/ebook/?error=Logout failed');
        }
        console.log(`✅ User ${username} logged out successfully`);
        res.redirect('/ebook/?success=Logged out successfully');
    });
};

// ✅ FIXED: Change Credentials Page
exports.changeCredentialsPage = (req, res) => {
    res.render('change-credentials', {
        title: 'Change Credentials',
        error: req.query.error,
        success: req.query.success,
        user: req.session.user,
        basePath: '/ebook'
    });
};

// ✅ FIXED: Change Credentials Handler with proper password hashing
exports.changeCredentials = async (req, res) => {
    try {
        const { currentPassword, newUsername, newPassword, confirmPassword } = req.body;
        const userId = req.session.user.id;

        console.log('🔄 Change credentials request for user ID:', userId);

        // Validation
        if (!currentPassword) {
            return res.redirect('/ebook/change-credentials?error=Current password is required');
        }

        if (!newUsername && !newPassword) {
            return res.redirect('/ebook/change-credentials?error=Please provide new username or password');
        }

        if (newPassword && newPassword !== confirmPassword) {
            return res.redirect('/ebook/change-credentials?error=New passwords do not match');
        }

        if (newPassword && newPassword.length < 6) {
            return res.redirect('/ebook/change-credentials?error=Password must be at least 6 characters long');
        }

        if (newUsername && newUsername.length < 3) {
            return res.redirect('/ebook/change-credentials?error=Username must be at least 3 characters long');
        }

        // Get user
        const user = await User.findById(userId);
        if (!user) {
            console.log('❌ User not found with ID:', userId);
            return res.redirect('/ebook/change-credentials?error=User not found');
        }

        console.log('🔍 Found user:', user.username);

        // Verify current password
        const isCurrentPasswordValid = await user.comparePassword(currentPassword);
        if (!isCurrentPasswordValid) {
            console.log('❌ Current password incorrect for user:', user.username);
            return res.redirect('/ebook/change-credentials?error=Current password is incorrect');
        }

        console.log('✅ Current password verified');

        let updatesMade = false;
        let successMessage = '';

        // Update username if provided and different
        if (newUsername && newUsername.trim() !== user.username) {
            const trimmedNewUsername = newUsername.trim();
            
            // Check if new username already exists
            const existingUser = await User.findOne({ 
                username: trimmedNewUsername, 
                _id: { $ne: userId } 
            });
            
            if (existingUser) {
                console.log('❌ Username already exists:', trimmedNewUsername);
                return res.redirect('/ebook/change-credentials?error=Username already exists');
            }

            // Update username using model method
            const usernameUpdated = await user.updateUsername(trimmedNewUsername);
            if (usernameUpdated) {
                updatesMade = true;
                successMessage += 'Username updated successfully. ';
                
                // Update session
                req.session.user.username = trimmedNewUsername;
                console.log(`✅ Username updated from ${user.username} to ${trimmedNewUsername}`);
            }
        }

        // Update password if provided
        if (newPassword) {
            // Use the model method to properly hash the password
            const passwordUpdated = await user.updatePassword(newPassword);
            if (passwordUpdated) {
                updatesMade = true;
                successMessage += 'Password updated successfully. ';
                console.log(`✅ Password updated for user ${user.username}`);
            } else {
                console.log('❌ Failed to update password');
                return res.redirect('/ebook/change-credentials?error=Failed to update password');
            }
        }

        if (updatesMade) {
            console.log(`✅ Credentials updated successfully for user: ${user.username}`);
            const finalMessage = successMessage.trim();
            res.redirect('/ebook/change-credentials?success=' + encodeURIComponent(finalMessage));
        } else {
            console.log('ℹ️ No changes made to credentials');
            res.redirect('/ebook/change-credentials?error=No changes made');
        }

    } catch (error) {
        console.error('❌ Change credentials error:', error);
        res.redirect('/ebook/change-credentials?error=Failed to update credentials: ' + error.message);
    }
};

// Get all users (admin only)
exports.getUsers = async (req, res) => {
    try {
        const users = await User.find({}, { password: 0 }).sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
};

// Create new user (admin only)
exports.createUser = async (req, res) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const existingUser = await User.findOne({ username: username.trim() });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const user = await User.create({
            username: username.trim(),
            password: password,
            role: role || 'user'
        });

        res.json({ 
            message: 'User created successfully',
            user: { id: user._id, username: user.username, role: user.role }
        });

    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
};

// Delete user (admin only)
exports.deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const currentUserId = req.session.user.id;

        // Prevent self-deletion
        if (id === currentUserId) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        await User.findByIdAndDelete(id);
        res.json({ message: 'User deleted successfully' });

    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
};

// ✅ ADDED: Emergency reset route (for testing)
exports.emergencyReset = async (req, res) => {
    try {
        const success = await User.resetToDefaultAdmin();
        if (success) {
            req.session.destroy(() => {
                res.redirect('/ebook/login?success=System reset to default admin: admin / admin123');
            });
        } else {
            res.redirect('/ebook/login?error=Failed to reset system');
        }
    } catch (error) {
        console.error('Emergency reset error:', error);
        res.redirect('/ebook/login?error=Emergency reset failed');
    }
};