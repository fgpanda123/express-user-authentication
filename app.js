const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Auth rate limiting (more restrictive)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // limit each IP to 5 auth requests per windowMs
});

// Environment variables (in production, use .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/express-auth';
const PORT = process.env.PORT || 3000;

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((error) => {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    });

// Handle MongoDB connection events
mongoose.connection.on('error', (error) => {
    console.error('MongoDB connection error:', error);
});

mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    try {
        await mongoose.connection.close();
        console.log('MongoDB connection closed through app termination');
        process.exit(0);
    } catch (error) {
        console.error('Error during graceful shutdown:', error);
        process.exit(1);
    }
});

// User Schema
const userSchema = new mongoose.Schema({
    // Basic Authentication Fields
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        minlength: [2, 'Name must be at least 2 characters long'],
        maxlength: [50, 'Name cannot exceed 50 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters long']
    },

    // Profile Information
    profile: {
        firstName: {
            type: String,
            trim: true,
            maxlength: [30, 'First name cannot exceed 30 characters']
        },
        lastName: {
            type: String,
            trim: true,
            maxlength: [30, 'Last name cannot exceed 30 characters']
        },
        displayName: {
            type: String,
            trim: true,
            maxlength: [50, 'Display name cannot exceed 50 characters']
        },
        bio: {
            type: String,
            trim: true,
            maxlength: [500, 'Bio cannot exceed 500 characters']
        },
        avatar: {
            type: String, // URL or base64 string
            validate: {
                validator: function(v) {
                    if (!v) return true;
                    // Check if it's a valid URL or base64 data URI
                    const urlRegex = /^https?:\/\/.+/;
                    const base64Regex = /^data:image\/(jpeg|jpg|png|gif|webp);base64,.+/;
                    return urlRegex.test(v) || base64Regex.test(v);
                },
                message: 'Avatar must be a valid URL or base64 data URI'
            }
        },
        dateOfBirth: {
            type: Date,
            validate: {
                validator: function(v) {
                    if (!v) return true;
                    return v < new Date();
                },
                message: 'Date of birth must be in the past'
            }
        },
        gender: {
            type: String,
            enum: ['male', 'female', 'other', 'prefer-not-to-say'],
            lowercase: true
        },
        phoneNumber: {
            type: String,
            trim: true,
            validate: {
                validator: function(v) {
                    if (!v) return true;
                    return /^\+?[\d\s\-\(\)]{10,15}$/.test(v);
                },
                message: 'Please enter a valid phone number'
            }
        }
    },

    // Address Information
    address: {
        street: {
            type: String,
            trim: true,
            maxlength: [100, 'Street address cannot exceed 100 characters']
        },
        city: {
            type: String,
            trim: true,
            maxlength: [50, 'City cannot exceed 50 characters']
        },
        state: {
            type: String,
            trim: true,
            maxlength: [50, 'State cannot exceed 50 characters']
        },
        zipCode: {
            type: String,
            trim: true,
            maxlength: [20, 'Zip code cannot exceed 20 characters']
        },
        country: {
            type: String,
            trim: true,
            maxlength: [50, 'Country cannot exceed 50 characters']
        }
    },

    // Social Links
    socialLinks: {
        website: {
            type: String,
            trim: true,
            validate: {
                validator: function(v) {
                    if (!v) return true;
                    return /^https?:\/\/.+/.test(v);
                },
                message: 'Website must be a valid URL'
            }
        },
        linkedin: {
            type: String,
            trim: true,
            validate: {
                validator: function(v) {
                    if (!v) return true;
                    return /^https?:\/\/(www\.)?linkedin\.com\//.test(v);
                },
                message: 'LinkedIn must be a valid LinkedIn URL'
            }
        },
        twitter: {
            type: String,
            trim: true,
            validate: {
                validator: function(v) {
                    if (!v) return true;
                    return /^https?:\/\/(www\.)?twitter\.com\//.test(v) || /^@?[A-Za-z0-9_]{1,15}$/.test(v);
                },
                message: 'Twitter must be a valid Twitter URL or username'
            }
        },
        github: {
            type: String,
            trim: true,
            validate: {
                validator: function(v) {
                    if (!v) return true;
                    return /^https?:\/\/(www\.)?github\.com\//.test(v) || /^[A-Za-z0-9_-]{1,39}$/.test(v);
                },
                message: 'GitHub must be a valid GitHub URL or username'
            }
        }
    },

    // Professional Information
    professional: {
        jobTitle: {
            type: String,
            trim: true,
            maxlength: [100, 'Job title cannot exceed 100 characters']
        },
        company: {
            type: String,
            trim: true,
            maxlength: [100, 'Company cannot exceed 100 characters']
        },
        industry: {
            type: String,
            trim: true,
            maxlength: [50, 'Industry cannot exceed 50 characters']
        },
        experience: {
            type: String,
            enum: ['entry-level', '1-2-years', '3-5-years', '6-10-years', '10+-years'],
            lowercase: true
        },
        skills: [{
            type: String,
            trim: true,
            maxlength: [30, 'Each skill cannot exceed 30 characters']
        }]
    },

    // Privacy Settings
    privacy: {
        profileVisibility: {
            type: String,
            enum: ['public', 'private', 'friends-only'],
            default: 'public'
        },
        showEmail: {
            type: Boolean,
            default: false
        },
        showPhone: {
            type: Boolean,
            default: false
        },
        showAddress: {
            type: Boolean,
            default: false
        }
    },

    // Account Status Fields
    isActive: {
        type: Boolean,
        default: true
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    isPhoneVerified: {
        type: Boolean,
        default: false
    },
    lastLogin: {
        type: Date
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    }
}, {
    timestamps: true // adds createdAt and updatedAt automatically
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ createdAt: -1 });

// Virtual for checking if account is locked
userSchema.virtual('isLocked').get(function() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
    // Only hash the password if it has been modified (or is new)
    if (!this.isModified('password')) return next();

    try {
        // Hash password with cost of 12
        this.password = await bcrypt.hash(this.password, 12);
        next();
    } catch (error) {
        next(error);
    }
});

// Instance method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Instance method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
    const maxAttempts = 5;
    const lockTime = 2 * 60 * 60 * 1000; // 2 hours

    // If we have a previous lock that has expired, restart at 1
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $set: {
                loginAttempts: 1
            },
            $unset: {
                lockUntil: 1
            }
        });
    }

    const updates = { $inc: { loginAttempts: 1 } };

    // If we have hit max attempts and it isn't locked already, lock the account
    if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
        updates.$set = { lockUntil: Date.now() + lockTime };
    }

    return this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
    return this.updateOne({
        $unset: {
            loginAttempts: 1,
            lockUntil: 1
        }
    });
};

// Instance method to get public profile (respects privacy settings)
userSchema.methods.getPublicProfile = function() {
    const userObject = this.toObject();
    delete userObject.password;
    delete userObject.loginAttempts;
    delete userObject.lockUntil;

    // Apply privacy settings
    if (!this.privacy.showEmail) {
        delete userObject.email;
    }
    if (!this.privacy.showPhone) {
        if (userObject.profile) delete userObject.profile.phoneNumber;
    }
    if (!this.privacy.showAddress) {
        delete userObject.address;
    }

    return userObject;
};

// Transform output to remove sensitive fields
userSchema.methods.toJSON = function() {
    const userObject = this.toObject();
    delete userObject.password;
    delete userObject.loginAttempts;
    delete userObject.lockUntil;
    return userObject;
};

const User = mongoose.model('User', userSchema);

// Token Blacklist Schema
const tokenBlacklistSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    expiresAt: {
        type: Date,
        required: true,
        expires: 0 // MongoDB will automatically delete documents when expiresAt is reached
    }
}, {
    timestamps: true
});

const TokenBlacklist = mongoose.model('TokenBlacklist', tokenBlacklistSchema);

// Utility functions
const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
};

const getTokenExpiry = (token) => {
    try {
        const decoded = jwt.decode(token);
        return new Date(decoded.exp * 1000);
    } catch (error) {
        return new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
    }
};

// Middleware to verify JWT token
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

// Input validation
const validatePassword = (password) => {
    // At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
};

// Routes

// Health check
app.get('/health', async (req, res) => {
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

// User registration
app.post('/api/auth/register', authLimiter, async (req, res) => {
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

// User login
app.post('/api/auth/login', authLimiter, async (req, res) => {
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

// Get current user profile
app.get('/api/auth/profile', authenticateToken, (req, res) => {
    try {
        res.json({ user: req.currentUser.toJSON() });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
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
app.put('/api/auth/basic-info', authenticateToken, async (req, res) => {
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

// Change password
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
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

// Logout (blacklist token)
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
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

// Delete account
app.delete('/api/auth/account', authenticateToken, async (req, res) => {
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

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
        message: 'This is a protected route',
        user: req.user,
        timestamp: new Date().toISOString()
    });
});

// Get all users (admin-like functionality)
app.get('/api/users', authenticateToken, async (req, res) => {
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

// Get public profile by user ID
app.get('/api/profile/:id', async (req, res) => {
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
app.get('/api/search/users', async (req, res) => {
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

// Upload/Update profile picture
app.post('/api/auth/avatar', authenticateToken, async (req, res) => {
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
app.put('/api/auth/privacy', authenticateToken, async (req, res) => {
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

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error:', err);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`MongoDB URI: ${MONGODB_URI}`);
});

module.exports = app;