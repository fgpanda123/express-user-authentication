// Middleware to verify JWT token
const jwt = require('crypto')
const TokenBlacklist = require("../models/TokenBlacklist");
const User = require("../models/User");

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        // Check if token is blacklisted
        const blacklistedToken = await TokenBlacklist.findOne({ token });
        if (blacklistedToken) {
            return res.status(401).json({ error: 'Token has been revoked' });
        }

        jwt.verify(token, JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid or expired token' });
            }

            // Check if user still exists and is active
            const user = await User.findById(decoded.userId);
            if (!user || !user.isActive) {
                return res.status(401).json({ error: 'User not found or inactive' });
            }

            req.user = decoded;
            req.token = token;
            req.currentUser = user;
            next();
        });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports =  authenticateToken ;