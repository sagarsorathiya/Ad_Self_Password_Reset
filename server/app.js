const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const cookieParser = require('cookie-parser');
const config = require('./config/default');
const { generalLimiter } = require('./middleware/rateLimiter');

// Import routes
const authRoutes = require('./routes/auth');
const enrollmentRoutes = require('./routes/enrollment');
const passwordRoutes = require('./routes/password');
const adminRoutes = require('./routes/admin');

const app = express();

if (config.server.trustProxy !== false) {
    app.set('trust proxy', config.server.trustProxy);
}

// ---- Security middleware ----
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            fontSrc: ["'self'"],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"],
            // Allow plain-HTTP intranet deployments; helmet's default would force HTTPS subresources
            upgradeInsecureRequests: config.server.https ? [] : null,
        },
    },
    hsts: config.server.https,
}));

// Same-origin by default; only enable CORS when explicit origins are configured
if (config.server.corsOrigins.length > 0) {
    app.use(cors({ origin: config.server.corsOrigins, credentials: true }));
}

// ---- Body parsing ----
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

// ---- Rate limiting ----
app.use('/api/', generalLimiter);

// Tokens, TOTP secrets and QR codes must never be stored by browsers or proxies
app.use('/api/', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    next();
});

// ---- API routes ----
app.use('/api/auth', authRoutes);
app.use('/api/enrollment', enrollmentRoutes);
app.use('/api/password', passwordRoutes);
app.use('/api/admin', adminRoutes);

// ---- Serve static frontend ----
app.use(express.static(path.join(__dirname, '..', 'public')));

// ---- SPA fallback: serve index.html for all non-API routes ----
app.get('/{*splat}', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            success: false,
            message: 'API endpoint not found.',
        });
    }
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ---- Global error handler ----
app.use((err, req, res, next) => {
    // Malformed JSON: err.body holds the raw request (may contain passwords), so never log the error object
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
        return res.status(err.status || 400).json({ success: false, message: 'Invalid request body.' });
    }
    console.error('[Server] Unhandled error:', err.message);
    res.status(500).json({
        success: false,
        message: process.env.NODE_ENV === 'development'
            ? err.message
            : 'An internal server error occurred.',
    });
});

module.exports = app;
