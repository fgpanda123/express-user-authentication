// Middleware to verify JWT token
const jwt = require('jsonwebtoken');
require('dotenv').config();
const TokenBlacklist = require("../models/TokenBlacklist");
const User = require("../models/User");

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({
                error: 'Authorization header missing',
                message: 'Please provide Authorization header with Bearer token'
            });
        }
        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Invalid authorization format',
                message: 'Authorization header must start with "Bearer "'
            });
        }

        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        console.log('Extracted token:', token ? 'Token exists' : 'Token is undefined');

        if (!token || token === 'undefined' || token === 'null') {
            return res.status(401).json({
                error: 'Token missing',
                message: 'No token provided in Authorization header'
            });
        }
        const JWT_SECRET = process.env.JWT_SECRET || '3ab8ed4e0f0399dd88b15cfdf4ba224ec8038570224dba3966bfa5e7d0b3ec71'

        if (!JWT_SECRET) {
            console.error('JWT_SECRET environment variable is not set');
            return res.status(500).json({
                error: 'Server configuration error',
                message: 'JWT secret not configured'
            });
        }

        console.log('JWT_SECRET exists:', !!JWT_SECRET);

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

            console.log('Token verified successfully for user:', decoded.userId || decoded.id);

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