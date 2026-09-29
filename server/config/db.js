const { Pool } = require('pg');
const config = require('./default');

const pool = new Pool({
    host: config.pg.host,
    port: config.pg.port,
    database: config.pg.database,
    user: config.pg.user,
    password: config.pg.password,
    max: config.pg.max,
    idleTimeoutMillis: config.pg.idleTimeoutMillis,
    ssl: config.pg.ssl,
});

pool.on('error', (err) => {
    console.error('[DB] Unexpected error on idle client:', err);
});

pool.on('connect', () => {
    if (config.server.env === 'development') {
        console.log('[DB] New client connected to PostgreSQL');
    }
});

/**
 * Execute a parameterized query.
 * @param {string} text - SQL query with $1, $2 placeholders
 * @param {Array} params - Parameter values
 * @returns {Promise<import('pg').QueryResult>}
 */
async function query(text, params) {
    const start = Date.now();
    const result = await pool.query(text, params);
    const duration = Date.now() - start;

    if (config.server.env === 'development') {
        console.log('[DB] Query executed', { text: text.substring(0, 80), duration: `${duration}ms`, rows: result.rowCount });
    }

    return result;
}

/**
 * Get a client from the pool for transactions.
 * Remember to release it when done.
 */
async function getClient() {
    return pool.connect();
}

module.exports = { pool, query, getClient };
