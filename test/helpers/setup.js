// Must be required before any server module: configures an isolated test environment.
const crypto = require('crypto');
require('../../server/config/secrets').loadSecrets();

process.env.NODE_ENV = 'test';
process.env.AD_MOCK = 'true';
process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.TOTP_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
process.env.PG_DATABASE = process.env.PG_TEST_DATABASE || `${process.env.PG_DATABASE || 'ad_password_reset'}_test`;
process.env.RATE_LIMIT_MAX = process.env.RATE_LIMIT_MAX_OVERRIDE || '1000';
process.env.RATE_LIMIT_GENERAL_MAX = '100000';
// Most tests exercise each method separately; reset-policy.test.js covers 'both' and 'totp_only'
process.env.RESET_POLICY = 'either';

// Tests truncate tables — never point them at a non-test database
if (!process.env.PG_DATABASE.endsWith('_test')) {
    throw new Error(`Refusing to run tests against non-test database "${process.env.PG_DATABASE}".`);
}

const fs = require('fs');
const path = require('path');
const otplib = require('otplib');
const { initDatabase } = require('../../scripts/init-db');

const SCHEMA_SQL = fs.readFileSync(path.join(__dirname, '..', '..', 'server', 'db', 'schema.sql'), 'utf8');

let app;
let db;
let mockAd;

async function startServer() {
    try {
        await initDatabase(process.env.PG_DATABASE);
    } catch (err) {
        throw new Error(
            `PostgreSQL is unavailable for integration tests (${err.message}). `
            + 'Set PG_HOST/PG_PORT/PG_USER/PG_PASSWORD in .env; the user needs CREATEDB permission.'
        );
    }

    app = require('../../server/app');
    db = require('../../server/config/db');
    mockAd = require('../../server/services/mockLdapService');

    const server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    return {
        baseUrl,
        request: (method, url, body, token) => request(baseUrl, method, url, body, token),
        async close() {
            server.closeAllConnections();
            await new Promise((resolve) => server.close(resolve));
            await db.pool.end();
        },
    };
}

async function resetState() {
    await db.query(
        'TRUNCATE users, user_security_answers, audit_log, used_reset_tokens, security_questions, password_exceptions RESTART IDENTITY CASCADE'
    );
    await db.query(SCHEMA_SQL);
    mockAd.reset();
}

async function request(baseUrl, method, url, body, token) {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(baseUrl + url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, body: json };
}

async function login(api, username, password) {
    const res = await api('POST', '/api/auth/login', { username, password });
    if (res.status !== 200) throw new Error(`Login failed for ${username}: ${res.body.message}`);
    return res.body.data;
}

const DEFAULT_ANSWERS = ['Rex', 'Springfield', 'Smith'];

// Fully enrolls a user (security questions + TOTP) and returns what the tests need.
async function enrollUser(api, username, password) {
    const { token } = await login(api, username, password);

    const questions = (await api('GET', '/api/enrollment/questions', undefined, token)).body.data;
    const selected = questions.slice(0, 3);
    const answers = selected.map((q, i) => ({ questionId: q.id, answer: DEFAULT_ANSWERS[i] }));

    const sq = await api('POST', '/api/enrollment/security-questions', { answers }, token);
    if (sq.status !== 200) throw new Error(`Security question enrollment failed: ${sq.body.message}`);

    const setup = await api('POST', '/api/enrollment/totp/setup', {}, token);
    const secret = setup.body.data.secret;
    const verify = await api('POST', '/api/enrollment/totp/verify', { code: totpCode(secret) }, token);
    if (verify.status !== 200) throw new Error(`TOTP enrollment failed: ${verify.body.message}`);

    return { token, secret, answers };
}

function totpCode(secret, offsetSeconds = 0) {
    return otplib.generateSync({ secret, epoch: Math.floor(Date.now() / 1000) + offsetSeconds });
}

module.exports = { startServer, resetState, login, enrollUser, totpCode, DEFAULT_ANSWERS };
