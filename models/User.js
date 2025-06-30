// User Schema
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs')

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
        index: true,
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

    // If we have hit max attempts, and it isn't locked already, lock the account
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

module.exports = User;