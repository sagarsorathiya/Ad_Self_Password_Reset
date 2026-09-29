const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const app = require('./app');
const config = require('./config/default');
const db = require('./config/db');
const ldapService = require('./services/ldapService');

const PORT = config.server.port;
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const fromRoot = (p) => path.resolve(__dirname, '..', p);

function createServer() {
    if (!config.server.https) return http.createServer(app);

    const tlsOptions = config.server.tlsPfxPath
        ? { pfx: fs.readFileSync(fromRoot(config.server.tlsPfxPath)), passphrase: config.server.tlsPfxPassphrase || undefined }
        : { cert: fs.readFileSync(fromRoot(config.server.tlsCertPath)), key: fs.readFileSync(fromRoot(config.server.tlsKeyPath)) };
    return https.createServer({ ...tlsOptions, minVersion: 'TLSv1.2' }, app);
}

async function checkServiceAccount() {
    if (config.ad.mock) return;
    try {
        if (!(await ldapService.isServiceAccountPrivileged())) return;
        const msg = `AD_BIND_DN (${config.ad.bindDN}) is a privileged account (adminCount=1, e.g. Domain Admins). `
            + 'Use a least-privilege service account: scripts/setup-ad-service-account.ps1';
        if (config.server.env === 'production' && process.env.AD_ALLOW_PRIVILEGED_BIND !== 'true') {
            console.error(`FATAL: ${msg}`);
            process.exit(1);
        }
        console.warn(`WARNING: ${msg}`);
    } catch (err) {
        console.warn(`WARNING: Could not verify the service account: ${err.message}`);
    }
}

async function cleanupExpiredTokens() {
    try {
        const result = await db.query('DELETE FROM used_reset_tokens WHERE expires_at < NOW()');
        if (result.rowCount > 0) console.log(`[Cleanup] Removed ${result.rowCount} expired reset token(s)`);
    } catch (err) {
        console.error('[Cleanup] Failed to purge expired reset tokens:', err.message);
    }
}

const server = createServer();
const scheme = config.server.https ? 'https' : 'http';

server.listen(PORT, config.server.host, () => {
    console.log('');
    console.log('AD Self-Service Password Reset Portal');
    console.log(`  URL:         ${scheme}://${config.server.host || 'localhost'}:${PORT}`);
    console.log(`  Environment: ${config.server.env}`);
    console.log(`  AD Server:   ${config.ad.mock ? 'MOCK (in-memory)' : config.ad.url}`);
    console.log(`  Trust proxy: ${config.server.trustProxy}`);
    console.log('');
    if (config.ad.mock) {
        console.warn('WARNING: AD_MOCK=true - using the in-memory test directory. Seed users: jsmith / Passw0rd!, admin / Adm1nPass!');
    }
    if (!config.server.https && config.server.env === 'production' && config.server.trustProxy === false) {
        console.warn('WARNING: Serving plain HTTP in production. Configure TLS_* or run behind an HTTPS reverse proxy.');
    }
    checkServiceAccount();
});

// Optional plain-HTTP listener that only redirects to HTTPS (no content is served over HTTP)
let redirectServer = null;
const redirectPort = parseInt(process.env.HTTP_REDIRECT_PORT, 10);
if (config.server.https && redirectPort) {
    redirectServer = http.createServer((req, res) => {
        const host = String(req.headers.host || '').replace(/:\d+$/, '');
        if (!/^[A-Za-z0-9.-]{1,253}$/.test(host)) {
            res.writeHead(400).end();
            return;
        }
        const portSuffix = PORT === 443 ? '' : `:${PORT}`;
        res.writeHead(301, { Location: `https://${host}${portSuffix}${req.url}` });
        res.end();
    }).listen(redirectPort, () => console.log(`  HTTP ${redirectPort} redirects to HTTPS ${PORT}`));
}

cleanupExpiredTokens();
const cleanupTimer = setInterval(cleanupExpiredTokens, CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

function shutdown(signal) {
    console.log(`[Server] ${signal} received, shutting down...`);
    clearInterval(cleanupTimer);
    redirectServer?.close();
    server.close(async () => {
        await db.pool.end().catch(() => {});
        process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
