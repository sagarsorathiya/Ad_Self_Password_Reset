require('./secrets').loadSecrets();
const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.join(__dirname, '..', '..');

function parseTrustProxy(value) {
    if (!value || value === 'false') return false;
    if (value === 'true') return true;
    return /^\d+$/.test(value) ? parseInt(value, 10) : value;
}

const config = {
    server: {
        port: parseInt(process.env.PORT, 10) || 3000,
        // 127.0.0.1 behind IIS/nginx so the Node port is not reachable from the network
        host: process.env.HOST || undefined,
        env: process.env.NODE_ENV || 'development',
        // Hops/subnets to trust for X-Forwarded-For (e.g. "1" or "loopback"); false when not behind a proxy
        trustProxy: parseTrustProxy(process.env.TRUST_PROXY),
        corsOrigins: (process.env.CORS_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean),
        https: Boolean((process.env.TLS_CERT_PATH && process.env.TLS_KEY_PATH) || process.env.TLS_PFX_PATH),
        tlsCertPath: process.env.TLS_CERT_PATH || '',
        tlsKeyPath: process.env.TLS_KEY_PATH || '',
        tlsPfxPath: process.env.TLS_PFX_PATH || '',
        tlsPfxPassphrase: process.env.TLS_PFX_PASSPHRASE || '',
    },

    ad: {
        url: process.env.AD_URL || 'ldap://localhost:389',
        baseDN: process.env.AD_BASE_DN || 'DC=domain,DC=com',
        bindDN: process.env.AD_BIND_DN || '',
        bindPassword: process.env.AD_BIND_PASSWORD || '',
        userSearchBase: process.env.AD_USER_SEARCH_BASE || 'OU=Users,DC=domain,DC=com',
        adminGroup: process.env.AD_ADMIN_GROUP || 'CN=PasswordResetAdmins,OU=Groups,DC=domain,DC=com',
        // TLS options for LDAPS / StartTLS
        tlsOptions: {
            rejectUnauthorized: process.env.AD_TLS_REJECT_UNAUTHORIZED !== 'false',
            // Internal CA root (PEM) that issued the DC certificate
            ca: process.env.AD_CA_CERT_PATH
                ? [fs.readFileSync(path.resolve(PROJECT_ROOT, process.env.AD_CA_CERT_PATH))]
                : undefined,
            // DC hostname on its certificate; needed when AD_URL uses an IP address
            servername: process.env.AD_TLS_SERVERNAME || undefined,
        },
        // Upgrade ldap:// (389) connections to TLS; AD refuses password writes without encryption
        startTls: process.env.AD_STARTTLS === 'true',
        // In-memory directory for local development/testing without a domain controller
        mock: process.env.AD_MOCK === 'true',
    },

    pg: {
        host: process.env.PG_HOST || 'localhost',
        port: parseInt(process.env.PG_PORT, 10) || 5432,
        database: process.env.PG_DATABASE || 'ad_password_reset',
        user: process.env.PG_USER || 'portal_user',
        password: process.env.PG_PASSWORD || '',
        max: 20,               // max pool size
        idleTimeoutMillis: 30000,
        // TLS to PostgreSQL when the database is on another host
        ssl: process.env.PG_SSL === 'true'
            ? {
                rejectUnauthorized: true,
                ca: process.env.PG_SSL_CA_PATH
                    ? fs.readFileSync(path.resolve(PROJECT_ROOT, process.env.PG_SSL_CA_PATH), 'utf8')
                    : undefined,
            }
            : false,
    },

    jwt: {
        secret: process.env.JWT_SECRET || 'CHANGE_THIS_SECRET',
        expiry: process.env.JWT_EXPIRY || '15m',
        refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
    },

    totp: {
        encryptionKey: process.env.TOTP_ENCRYPTION_KEY || '',
        issuer: process.env.TOTP_ISSUER || 'AD Password Reset Portal',
    },

    rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000, // 15 minutes
        max: parseInt(process.env.RATE_LIMIT_MAX, 10) || 5,
        generalMax: parseInt(process.env.RATE_LIMIT_GENERAL_MAX, 10) || 100,
    },

    // Account lockout after too many failed verification attempts
    lockout: {
        maxAttempts: 5,
        lockoutDurationMs: 30 * 60 * 1000, // 30 minutes
    },

    // Identity proof required for a password reset:
    //   both      security questions AND authenticator code (default, strongest)
    //   totp_only authenticator code only
    //   either    security questions OR authenticator code
    reset: {
        policy: process.env.RESET_POLICY || 'both',
    },
};

if (!['both', 'totp_only', 'either'].includes(config.reset.policy)) {
    throw new Error('RESET_POLICY must be one of: both, totp_only, either.');
}

if (config.totp.encryptionKey && !/^[0-9a-fA-F]{64}$/.test(config.totp.encryptionKey)) {
    throw new Error('TOTP_ENCRYPTION_KEY must be exactly 64 hex characters (256-bit key).');
}

// User passwords are sent in every bind; never talk to a real directory unencrypted
const adEncrypted = config.ad.url.startsWith('ldaps://') || (config.ad.startTls && config.ad.url.startsWith('ldap://'));
if (!config.ad.mock && !adEncrypted) {
    throw new Error('AD connection must be encrypted: use ldaps:// or set AD_STARTTLS=true with ldap://.');
}

if (config.server.env === 'production') {
    if (config.ad.mock) {
        throw new Error('AD_MOCK cannot be enabled in production.');
    }
    if (!config.ad.tlsOptions.rejectUnauthorized) {
        throw new Error('AD_TLS_REJECT_UNAUTHORIZED=false is not allowed in production; trust the CA via AD_CA_CERT_PATH.');
    }
    if (!config.server.https && config.server.trustProxy === false) {
        throw new Error('Production requires HTTPS: set TLS_PFX_PATH (or TLS_CERT_PATH/TLS_KEY_PATH), or TRUST_PROXY when an HTTPS reverse proxy terminates TLS.');
    }
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
        throw new Error('JWT_SECRET must be set to at least 32 characters in production.');
    }
    if (!config.totp.encryptionKey) {
        throw new Error('TOTP_ENCRYPTION_KEY must be set in production.');
    }
}

module.exports = config;
