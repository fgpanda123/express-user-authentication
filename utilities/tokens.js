const jwt = require("jsonwebtoken");
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

exports.getTokenExpiry = getTokenExpiry;
exports.generateToken = generateToken;