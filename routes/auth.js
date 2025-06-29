const express = require('express');
const authenticateToken = require("../middlewares/authentication");
const {validatePassword} = require("../input_validation/validate_password");
const User = require("../models/User");
const {generateToken, getTokenExpiry} = require("../utilities/tokens");
const TokenBlacklist = require("../models/TokenBlacklist");
const authenticationRouter = express.Router();
// Auth rate limiting (more restrictive)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // limit each IP to 5 auth requests per windowMs
});

authenticationRouter.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const { email, password, name } = req.body;

        // Validation
        if (!email || !password || !name) {
            return res.status(400).json({
                error: 'All fields are required',
                required_fields: ['email', 'password', 'name']
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                error: 'Password must be at least 8 characters long and contain uppercase, lowercase, and number'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists with this email' });
        }

        // Create user (password will be hashed by pre-save middleware)
        const newUser = new User({
            email: email.toLowerCase(),
            password,
            name: name.trim()
        });

        await newUser.save();

        // Generate token
        const token = generateToken(newUser._id);

        res.status(201).json({
            message: 'User registered successfully',
            user: newUser.toJSON(),
            token
        });

    } catch (error) {
        console.error('Registration error:', error);

        // Handle mongoose validation errors
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ error: errors[0] });
        }

        // Handle duplicate key error
        if (error.code === 11000) {
            return res.status(409).json({ error: 'Email already exists' });
        }

        res.status(500).json({ error: 'Internal server error' });
    }
});

authenticationRouter.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({
                error: 'Email and password are required'
            });
        }

        // Find user
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.isActive) {
            return res.status(401).json({ error: 'Account is deactivated' });
        }

        // Check if account is locked
        if (user.isLocked) {
            return res.status(423).json({ error: 'Account temporarily locked due to too many failed login attempts' });
        }

        // Check password
        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            // Increment login attempts
            await user.incLoginAttempts();
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Reset login attempts on successful login
        if (user.loginAttempts > 0) {
            await user.resetLoginAttempts();
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate token
        const token = generateToken(user._id);

        res.json({
            message: 'Login successful',
            user: user.toJSON(),
            token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout (blacklist token)
authenticationRouter.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        const tokenExpiry = getTokenExpiry(req.token);

        await TokenBlacklist.create({
            token: req.token,
            expiresAt: tokenExpiry
        });

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default authenticationRouter;