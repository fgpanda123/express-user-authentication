# setup
    # bash
    npm init -y
    npm install express mongoose bcryptjs jsonwebtoken cors helmet express-rate-limit
---
# start mongodb
    docker run -d -p 27017:27017 --name mongodb mongo:latest

---
## Or install MongoDB locally

    https://docs.mongodb.com/manual/installation/
---
# set environment variables (optional .env file)
    MONGODB_URI=mongodb://localhost:27017/express-auth
    JWT_SECRET=your-super-secret-jwt-key
    PORT=3000
---
# run the server
    node app.js
---
# user schema
    {
        name: String (required, 2-50 chars), 
        email: String (required, unique, validated), 
        password: String (required, hashed), 
        isActive: Boolean (default: true), 
        lastLogin: Date, 
        loginAttempts: Number (default: 0), 
        lockUntil: Date, 
        createdAt: Date (auto), 
        updatedAt: Date (auto) 
    }
---
# tokenBlacklist schema
    {    
        token: String (required, unique), 
        expiresAt: Date (required, TTL index), 
        createdAt: Date (auto) 
    }
---
# Testing api

## Register a user
    curl -X POST http://localhost:3000/api/auth/register
    -H "Content-Type: application/json" 
    -d '{"name":"John Doe","email":"john@example.com","password":"Password123"}'

## Login
    curl -X POST http://localhost:3000/api/auth/login 
    -H "Content-Type: application/json" 
    -d '{"email":"john@example.com","password":"Password123"}'

## Get users with pagination
    curl -X GET "http://localhost:3000/api/users?page=1&limit=5" 
    -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 👤 Enhanced User Profile Schema
## Personal Information

firstName, lastName, displayName 
bio (up to 500 characters) \
avatar (URL or base64 image) \
dateOfBirth, gender, phoneNumber

## Address Information

Complete address fields: street, city, state, zipCode, country

## Social Links

website, linkedin, twitter, github
Automatic validation for proper URLs/usernames

## Professional Information

jobTitle, company, industry \
experience level (entry-level to 10+ years) \
skills array (up to 20 skills) 

## Privacy Settings

profileVisibility (public/private/friends-only) \
Control visibility of email, phone, and address
---
# 🔐 New API Endpoints
## Profile Management

```PUT /api/auth/profile - Update comprehensive profile data ``` \
```PUT /api/auth/basic-info - Update name/email (sensitive changes) ``` \
```POST /api/auth/avatar - Upload/update profile picture ``` \
```PUT /api/auth/privacy - Update privacy settings ```

## Public Profile & Search

```GET /api/profile/:id - Get public profile (respects privacy)```

```GET /api/search/users - Search users by name, skills, company```

# 🔍 Search Functionality
The search endpoint supports multiple parameters:
## Search by name or bio
```GET /api/search/users?q=john```

## Search by skills
```GET /api/search/users?skills=javascript,node.js```

## Search by company
```GET /api/search/users?company=google ```

## Combined search with pagination
```GET /api/search/users?q=developer&skills=react&page=1&limit=5 ```

# 📝 Example Usage
## Update Profile
    curl -X PUT http://localhost:3000/api/auth/profile 
        -H "Authorization: Bearer YOUR_JWT_TOKEN" 
        -H "Content-Type: application/json" 
        -d '{
                "profile": {
                    "firstName": "John",
                    "lastName": "Doe",
                    "displayName": "Johnny",
                    "bio": "Full-stack developer passionate about web technologies",
                    "dateOfBirth": "1990-01-15",
                    "gender": "male",
                    "phoneNumber": "+1-555-0123"
            },
                "address": { 
                    "street": "123 Main St",
                    "city": "San Francisco",
                    "state": "CA",
                    "zipCode": "94105",
                    "country": "USA" 
            },
                "socialLinks": { 
                    "website": "https://johndoe.dev", 
                    "linkedin": "https://linkedin.com/in/johndoe", 
                    "github": "johndoe" 
            }, 
                "professional": { 
                    "jobTitle": "Senior Full-Stack Developer", 
                    "company": "Tech Corp", 
                    "industry": "Technology", 
                    "experience": "6-10-years", 
                    "skills": ["JavaScript", "React", "Node.js", "MongoDB", "Python"] 
            } 
    }'
# Update Avatar
    curl -X POST http://localhost:3000/api/auth/avatar 
        -H "Authorization: Bearer YOUR_JWT_TOKEN" 
        -H "Content-Type: application/json" 
        -d '{
                "avatar": "https://example.com/avatar.jpg"
            }'
---
# Update Privacy Settings
    curl -X PUT http://localhost:3000/api/auth/privacy 
        -H "Authorization: Bearer YOUR_JWT_TOKEN" 
        -H "Content-Type: application/json" 
        -d '{
                "profileVisibility": "public",
                "showEmail": false,
                "showPhone": false,
                "showAddress": true
            }'
---
# 🛡️ Privacy & Security Features
## Privacy Controls
Users can set profile visibility (public/private/friends-only)
Granular control over what information is publicly visible
Separate method getPublicProfile() respects privacy settings

## Data Validation
Comprehensive validation for all profile fields
URL validation for social links and avatar
Phone number format validation
Skills array limited to 20 items max

## Security Improvements
Email verification status tracking
Phone verification status tracking
Sensitive data separated from public profile endpoints

# 📊 Database Indexes
The schema includes optimized indexes for:
Email lookups
User search by name and skills
Profile visibility filtering
Creation date sorting

This enhanced profile system provides a solid foundation for a social platform, professional network, or any application requiring detailed user profiles with privacy controls.