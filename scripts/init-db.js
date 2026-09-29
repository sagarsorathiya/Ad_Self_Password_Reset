// Creates the database if missing and applies server/db/schema.sql.
// Usage: node scripts/init-db.js [databaseName]
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const SCHEMA_PATH = path.join(__dirname, '..', 'server', 'db', 'schema.sql');

function connectionOptions(database) {
    return {
        host: process.env.PG_HOST || 'localhost',
        port: parseInt(process.env.PG_PORT, 10) || 5432,
        user: process.env.PG_USER || 'portal_user',
        password: process.env.PG_PASSWORD || '',
        database,
    };
}

async function initDatabase(database) {
    if (!/^[A-Za-z0-9_]+$/.test(database)) {
        throw new Error(`Invalid database name: ${database}`);
    }

    const admin = new Client(connectionOptions(process.env.PG_ADMIN_DATABASE || 'postgres'));
    await admin.connect();
    try {
        const exists = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [database]);
        if (exists.rows.length === 0) {
            await admin.query(`CREATE DATABASE "${database}"`);
            console.log(`[init-db] Created database ${database}`);
        }
    } finally {
        await admin.end();
    }

    const client = new Client(connectionOptions(database));
    await client.connect();
    try {
        await client.query(fs.readFileSync(SCHEMA_PATH, 'utf8'));
    } finally {
        await client.end();
    }
}

module.exports = { initDatabase };

if (require.main === module) {
    require('../server/config/secrets').loadSecrets();
    const database = process.argv[2] || process.env.PG_DATABASE || 'ad_password_reset';
    initDatabase(database)
        .then(() => console.log(`[init-db] Schema applied to ${database}`))
        .catch((err) => {
            console.error(`[init-db] Failed: ${err.message}`);
            process.exit(1);
        });
}
