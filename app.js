const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const accountRouter = require('./routes/account');
const authenticationRouter = require('./routes/auth');
const profileRouter = require('./routes/profile');
const searchRouter = require('./routes/search');
const testRouter = require('./routes/test');
const app = express();
// Environment variables (in production, use .env file)
const JWT_SECRET = process.env.JWT_SECRET || '3ab8ed4e0f0399dd88b15cfdf4ba224ec8038570224dba3966bfa5e7d0b3ec71'
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://peterwu91695:poEQxY5kUkKGbi3M@cluster0.psudhu3.mongodb.net/myDatabase?retryWrites=true&w=majority&appName=Cluster0';
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

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);

// Routes

app.use('/', accountRouter);
app.use('/', authenticationRouter);
app.use('/', profileRouter);
app.use('/', searchRouter);
app.use('/', testRouter);
app.get('/', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    res.json({
        authHeader,
        token
    })

});

// 404 handler
/* app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});
*/
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
module.exports.JWT_SECRET = JWT_SECRET;
module.exports.MONGODB_URI = MONGODB_URI;
module.exports.app = app;
