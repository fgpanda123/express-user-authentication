const jwt = require("jsonwebtoken");
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET || '3ab8ed4e0f0399dd88b15cfdf4ba224ec8038570224dba3966bfa5e7d0b3ec71';
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

module.exports = {getTokenExpiry, generateToken};
