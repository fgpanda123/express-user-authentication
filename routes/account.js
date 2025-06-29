const express = require('express');
const authenticateToken = require("../middlewares/authentication");
const {validatePassword} = require("../input_validation/validate_password");
const User = require("../models/User");
const TokenBlacklist = require("../models/TokenBlacklist");
const accountRouter = express.Router();

// Change password
accountRouter.put('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = req.currentUser;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current password and new password are required' });
        }

        if (!validatePassword(newPassword)) {
            return res.status(400).json({
                error: 'New password must be at least 8 characters long and contain uppercase, lowercase, and number'
            });
        }

        // Verify current password
        const isValidPassword = await user.comparePassword(currentPassword);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Update password (will be hashed by pre-save middleware)
        user.password = newPassword;
        await user.save();

        res.json({ message: 'Password changed successfully' });

    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete account
accountRouter.delete('/api/auth/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        const user = req.currentUser;

        if (!password) {
            return res.status(400).json({ error: 'Password is required to delete account' });
        }

        // Verify password
        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Soft delete - deactivate account
        await User.findByIdAndUpdate(user._id, { isActive: false });

        // Blacklist current token
        const tokenExpiry = getTokenExpiry(req.token);
        await TokenBlacklist.create({
            token: req.token,
            expiresAt: tokenExpiry
        });

        res.json({ message: 'Account deleted successfully' });

    } catch (error) {
        console.error('Account deletion error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default accountRouter;