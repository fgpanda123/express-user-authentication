const mongoose = require('mongoose');
const express = require('express');
const authenticateToken = require("../middlewares/authentication");
const User = require("../models/User");
const {generateToken} = require("../utilities/tokens");
const testRouter = express.Router();
// Get all users (admin-like functionality)
testRouter.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const users = await User.find({ isActive: true })
            .select('-password -loginAttempts -lockUntil')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await User.countDocuments({ isActive: true });

        res.json({
            users,
            pagination: {
                current: page,
                total: Math.ceil(total / limit),
                count: users.length,
                totalUsers: total
            }
        });
    } catch (error) {
        console.error('Users fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

testRouter.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
        message: 'This is a protected route',
        user: req.user,
        timestamp: new Date().toISOString()
    });
});

testRouter.get('/health', async (req, res) => {
    try {
        // Check database connection
        const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
        const userCount = await User.countDocuments();

        res.json({
            status: 'OK',
            database: dbStatus,
            userCount,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(503).json({
            status: 'ERROR',
            database: 'error',
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = testRouter;