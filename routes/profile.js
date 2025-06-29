const express = require('express');
const authenticateToken = require("../middlewares/authentication");
const User = require("../models/User");
const profileRouter = express.Router();

// Get current user profile
profileRouter.get('/api/auth/profile', authenticateToken, (req, res) => {
    try {
        res.json({ user: req.currentUser.toJSON() });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user profile
profileRouter.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = req.currentUser;
        const updateData = req.body;

        // Remove sensitive fields that shouldn't be updated through this endpoint
        delete updateData.password;
        delete updateData.email;
        delete updateData.isActive;
        delete updateData.loginAttempts;
        delete updateData.lockUntil;
        delete updateData.isEmailVerified;
        delete updateData.isPhoneVerified;

        // Validate skills array if provided
        if (updateData.professional && updateData.professional.skills) {
            if (!Array.isArray(updateData.professional.skills)) {
                return res.status(400).json({ error: 'Skills must be an array' });
            }
            if (updateData.professional.skills.length > 20) {
                return res.status(400).json({ error: 'Maximum 20 skills allowed' });
            }
        }

        // Update user with nested object support
        const updatedUser = await User.findByIdAndUpdate(
            user._id,
            { $set: updateData },
            {
                new: true,
                runValidators: true,
                context: 'query' // Required for proper validation of nested objects
            }
        );

        res.json({
            message: 'Profile updated successfully',
            user: updatedUser.toJSON()
        });

    } catch (error) {
        console.error('Profile update error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ error: errors[0] });
        }

        if (error.name === 'CastError') {
            return res.status(400).json({ error: 'Invalid data format' });
        }

        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update basic info (name, email) - separate endpoint for sensitive changes
profileRouter.put('/api/auth/basic-info', authenticateToken, async (req, res) => {
    try {
        const { name, email } = req.body;
        const user = req.currentUser;

        // Validate inputs
        if (name && name.trim().length < 2) {
            return res.status(400).json({ error: 'Name must be at least 2 characters long' });
        }

        // Check if email is already taken by another user
        if (email && email.toLowerCase() !== user.email) {
            const existingUser = await User.findOne({
                email: email.toLowerCase(),
                _id: { $ne: user._id }
            });
            if (existingUser) {
                return res.status(409).json({ error: 'Email is already taken' });
            }
        }

        // Update user
        const updateData = {};
        if (name) updateData.name = name.trim();
        if (email) {
            updateData.email = email.toLowerCase();
            updateData.isEmailVerified = false; // Reset verification when email changes
        }

        const updatedUser = await User.findByIdAndUpdate(
            user._id,
            updateData,
            { new: true, runValidators: true }
        );

        res.json({
            message: 'Basic information updated successfully',
            user: updatedUser.toJSON()
        });

    } catch (error) {
        console.error('Basic info update error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ error: errors[0] });
        }

        if (error.code === 11000) {
            return res.status(409).json({ error: 'Email already exists' });
        }

        res.status(500).json({ error: 'Internal server error' });
    }
});

// Upload/Update profile picture
profileRouter.post('/api/auth/avatar', authenticateToken, async (req, res) => {
    try {
        const { avatar } = req.body;
        const user = req.currentUser;

        if (!avatar) {
            return res.status(400).json({ error: 'Avatar data is required' });
        }

        // Validate avatar format (URL or base64)
        const urlRegex = /^https?:\/\/.+/;
        const base64Regex = /^data:image\/(jpeg|jpg|png|gif|webp);base64,.+/;

        if (!urlRegex.test(avatar) && !base64Regex.test(avatar)) {
            return res.status(400).json({ error: 'Avatar must be a valid URL or base64 data URI' });
        }

        // Update avatar
        const updatedUser = await User.findByIdAndUpdate(
            user._id,
            { 'profile.avatar': avatar },
            { new: true, runValidators: true }
        );

        res.json({
            message: 'Avatar updated successfully',
            avatar: updatedUser.profile.avatar
        });

    } catch (error) {
        console.error('Avatar update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update privacy settings
profileRouter.put('/api/auth/privacy', authenticateToken, async (req, res) => {
    try {
        const { profileVisibility, showEmail, showPhone, showAddress } = req.body;
        const user = req.currentUser;

        const privacyUpdate = {};
        if (profileVisibility !== undefined) privacyUpdate['privacy.profileVisibility'] = profileVisibility;
        if (showEmail !== undefined) privacyUpdate['privacy.showEmail'] = showEmail;
        if (showPhone !== undefined) privacyUpdate['privacy.showPhone'] = showPhone;
        if (showAddress !== undefined) privacyUpdate['privacy.showAddress'] = showAddress;

        const updatedUser = await User.findByIdAndUpdate(
            user._id,
            privacyUpdate,
            { new: true, runValidators: true }
        );

        res.json({
            message: 'Privacy settings updated successfully',
            privacy: updatedUser.privacy
        });

    } catch (error) {
        console.error('Privacy update error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ error: errors[0] });
        }

        res.status(500).json({ error: 'Internal server error' });
    }
});

export default profileRouter;