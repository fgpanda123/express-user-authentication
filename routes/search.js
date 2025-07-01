const express = require('express');
const User = require("../models/User");
const searchRouter = express.Router();
const mongoose = require("mongoose");

// Get public profile by user ID
searchRouter.get('/api/profile/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        const user = await User.findById(req.params.id);

        if (!user || !user.isActive) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check privacy settings
        if (user.privacy.profileVisibility === 'private') {
            return res.status(403).json({ error: 'This profile is private' });
        }

        res.json({ user: user.getPublicProfile() });
    } catch (error) {
        console.error('Public profile fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Search users by name, skills, or company
searchRouter.get('/api/search/users', async (req, res) => {
    try {
        const { q, skills, company, page = 1, limit = 10 } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Build search query
        const searchQuery = {
            isActive: true,
            'privacy.profileVisibility': { $in: ['public'] }
        };

        if (q) {
            searchQuery.$or = [
                { name: { $regex: q, $options: 'i' } },
                { 'profile.displayName': { $regex: q, $options: 'i' } },
                { 'profile.bio': { $regex: q, $options: 'i' } },
                { 'professional.jobTitle': { $regex: q, $options: 'i' } }
            ];
        }

        if (skills) {
            const skillsArray = skills.split(',').map(s => s.trim());
            searchQuery['professional.skills'] = { $in: skillsArray.map(skill => new RegExp(skill, 'i')) };
        }

        if (company) {
            searchQuery['professional.company'] = { $regex: company, $options: 'i' };
        }

        const users = await User.find(searchQuery)
            .select('-password -loginAttempts -lockUntil -email -address -profile.phoneNumber')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        const total = await User.countDocuments(searchQuery);

        res.json({
            users: users.map(user => user.getPublicProfile()),
            pagination: {
                current: parseInt(page),
                total: Math.ceil(total / parseInt(limit)),
                count: users.length,
                totalUsers: total
            }
        });
    } catch (error) {
        console.error('User search error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = searchRouter;