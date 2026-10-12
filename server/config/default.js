require('./secrets').loadSecrets();
const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.join(__dirname, '..', '..');

function parseTrustProxy(value) {
    if (!value || value === 'false') return false;
    if (value === 'true') return true;
    return /^\d+$/.test(value) ? parseInt(value, 10) : value;
}

// Connection settings for one domain, read from <prefix>_URL, <prefix>_BIND_DN, ...
function buildAdConfig(prefix, defaultName) {
    const env = (name) => process.env[`${prefix}_${name}`];
    return {
        name: env('DOMAIN_LABEL') || defaultName,
        url: env('URL') || 'ldap://localhost:389',
        baseDN: env('BASE_DN') || 'DC=domain,DC=com',
        bindDN: env('BIND_DN') || '',
        bindPassword: env('BIND_PASSWORD') || '',
        userSearchBase: env('USER_SEARCH_BASE') || 'OU=Users,DC=domain,DC=com',
        // TLS options for LDAPS / StartTLS
        tlsOptions: {
            rejectUnauthorized: env('TLS_REJECT_UNAUTHORIZED') !== 'false',
            // Internal CA root (PEM) that issued the DC certificate
            ca: env('CA_CERT_PATH')
                ? [fs.readFileSync(path.resolve(PROJECT_ROOT, env('CA_CERT_PATH')))]
                : undefined,
            // DC hostname on its certificate; needed when the URL uses an IP address
            servername: env('TLS_SERVERNAME') || undefined,
        },
        // Upgrade ldap:// (389) connections to TLS; AD refuses password writes without encryption
        startTls: env('STARTTLS') === 'true',
        // 'ldap': ldapjs over LDAPS/StartTLS. 'windows': ADSI with Kerberos/NTLM sign-and-seal on 389 (no certificate)
        mode: env('MODE') || 'ldap',
        // windows mode: the writable DC to use (hostname preferred so Kerberos is used)
        server: env('SERVER') || '',
        // windows mode: empty = the domain root (defaultNamingContext)
        rawSearchBase: env('USER_SEARCH_BASE') || '',
    };
}

const isAdEncrypted = (ad) => ad.url.startsWith('ldaps://') || (ad.startTls && ad.url.startsWith('ldap://'));

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
        ...buildAdConfig('AD', 'Active Directory'),
        adminGroup: process.env.AD_ADMIN_GROUP || 'CN=PasswordResetAdmins,OU=Groups,DC=domain,DC=com',
        // In-memory directory for local development/testing without a domain controller
        mock: process.env.AD_MOCK === 'true',
        // Optional second domain (AD2_*) that receives the same password on every change and reset.
        // Users are matched by sAMAccountName; sign-in and admin rights always use the first domain.
        secondary: process.env.AD2_URL || process.env.AD2_SERVER ? buildAdConfig('AD2', 'Secondary domain') : null,
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
if (!config.ad.mock && !isAdEncrypted(config.ad)) {
    throw new Error('AD connection must be encrypted: use ldaps:// or set AD_STARTTLS=true with ldap://.');
}
const secondary = config.ad.secondary;
if (secondary && !['ldap', 'windows'].includes(secondary.mode)) {
    throw new Error('AD2_MODE must be ldap or windows.');
}
if (!config.ad.mock && secondary?.mode === 'ldap' && !isAdEncrypted(secondary)) {
    throw new Error('AD2 connection must be encrypted: use ldaps:// or set AD2_STARTTLS=true with ldap://.');
}
// windows mode is encrypted by Kerberos/NTLM sealing (the helper requests it and the bind fails without it)
if (!config.ad.mock && secondary?.mode === 'windows') {
    if (process.platform !== 'win32') throw new Error('AD2_MODE=windows requires Windows.');
    if (!secondary.server || !secondary.bindDN || !secondary.bindPassword) {
        throw new Error('AD2_MODE=windows requires AD2_SERVER, AD2_BIND_DN (DOMAIN\\user or user@domain) and AD2_BIND_PASSWORD.');
    }
    if (/^CN=/i.test(secondary.bindDN)) {
        throw new Error('AD2_MODE=windows: set AD2_BIND_DN to DOMAIN\\user or user@domain, not a distinguished name.');
    }
}

if (config.server.env === 'production') {
    if (config.ad.mock) {
        throw new Error('AD_MOCK cannot be enabled in production.');
    }
    if (!config.ad.tlsOptions.rejectUnauthorized) {
        throw new Error('AD_TLS_REJECT_UNAUTHORIZED=false is not allowed in production; trust the CA via AD_CA_CERT_PATH.');
    }
    if (secondary?.mode === 'ldap' && !secondary.tlsOptions.rejectUnauthorized) {
        throw new Error('AD2_TLS_REJECT_UNAUTHORIZED=false is not allowed in production; trust the CA via AD2_CA_CERT_PATH.');
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
