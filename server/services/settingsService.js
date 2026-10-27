// Runtime settings an admin can change in Administration -> Mail & Reminders, stored in app_settings and
// layered over the .env defaults from config/default.js: a key that was never saved keeps the .env value.
// Everything reads the in-memory snapshot (current()), which is loaded at startup and refreshed after every
// save and on every reminder tick, so a change applies without restarting the portal.
const db = require('../config/db');
const config = require('../config/default');
const cryptoService = require('./cryptoService');

// Returned instead of the stored SMTP password; sending it back unchanged keeps the stored value
const SECRET_PLACEHOLDER = '********';
const MAX_STAGES = 31;

function invalid(message) {
    const err = new Error(message);
    err.validation = true;
    return err;
}

function parseBoolean(raw, label) {
    if (typeof raw === 'boolean') return raw;
    if (raw === 'true' || raw === 'false') return raw === 'true';
    throw invalid(`${label} must be true or false.`);
}

function parseInteger(raw, label, min, max) {
    const value = typeof raw === 'number' ? raw : parseInt(String(raw).trim(), 10);
    if (!Number.isInteger(value) || value < min || value > max) {
        throw invalid(`${label} must be a whole number between ${min} and ${max}.`);
    }
    return value;
}

function parseText(raw, label, maxLength) {
    const value = String(raw ?? '').trim();
    if (value.length > maxLength) throw invalid(`${label} must be at most ${maxLength} characters.`);
    return value;
}

// "14, 7, 3, 1" or [14, 7, 3, 1] -> sorted, de-duplicated descending stage list
function parseDays(raw, label) {
    const list = Array.isArray(raw) ? raw : String(raw ?? '').split(',');
    const days = [];
    for (const item of list) {
        if (String(item).trim() === '') continue;
        const day = parseInteger(item, `Each value in ${label}`, 1, 365);
        if (!days.includes(day)) days.push(day);
    }
    if (days.length === 0) throw invalid(`${label} must list at least one day before expiry.`);
    if (days.length > MAX_STAGES) throw invalid(`${label} can list at most ${MAX_STAGES} days.`);
    return days.sort((a, b) => b - a);
}

/**
 * The editable keys: where each one lives in the snapshot, how it is validated, and how it is stored.
 * secret: stored encrypted and never sent to the client.
 */
const FIELDS = {
    'mail.host': { group: 'mail', name: 'host', label: 'SMTP host', parse: (v) => parseText(v, 'SMTP host', 255) },
    'mail.port': { group: 'mail', name: 'port', label: 'SMTP port', parse: (v) => parseInteger(v, 'SMTP port', 1, 65535) },
    'mail.secure': { group: 'mail', name: 'secure', label: 'Implicit TLS', parse: (v) => parseBoolean(v, 'Implicit TLS') },
    'mail.user': { group: 'mail', name: 'user', label: 'SMTP username', parse: (v) => parseText(v, 'SMTP username', 255) },
    'mail.password': {
        group: 'mail', name: 'password', label: 'SMTP password', secret: true,
        parse: (v) => parseText(v, 'SMTP password', 255),
    },
    'mail.from': { group: 'mail', name: 'from', label: 'From address', parse: (v) => parseText(v, 'From address', 255) },
    'reminders.enabled': {
        group: 'reminders', name: 'enabled', label: 'Expiry reminders',
        parse: (v) => parseBoolean(v, 'Expiry reminders'),
    },
    'reminders.days': {
        group: 'reminders', name: 'days', label: 'Days before expiry',
        parse: (v) => parseDays(v, 'Days before expiry'),
        serialize: (v) => v.join(','),
        deserialize: (v) => parseDays(v, 'Days before expiry'),
    },
    'reminders.hour': { group: 'reminders', name: 'hour', label: 'Daily run hour', parse: (v) => parseInteger(v, 'Daily run hour', 0, 23) },
    'reminders.source': {
        group: 'reminders', name: 'source', label: 'Expiry source',
        parse: (v) => {
            const value = parseText(v, 'Expiry source', 20).toLowerCase();
            if (value !== 'primary' && value !== 'secondary') throw invalid('Expiry source must be primary or secondary.');
            if (value === 'secondary' && !config.ad.secondary) throw invalid('Expiry source "secondary" needs a second domain (AD2_*).');
            return value;
        },
    },
};

function defaults() {
    return {
        mail: { ...config.mail },
        reminders: { ...config.reminders, days: [...config.reminders.days] },
        // Keys whose value comes from the database rather than .env
        overrides: [],
    };
}

let snapshot = defaults();

function current() {
    return snapshot;
}

/**
 * Reload the snapshot from app_settings. Values that fail validation (hand-edited rows, a key that is no
 * longer allowed) are ignored and reported, so a bad row can never stop mail or the reminder run.
 * @returns {Promise<object>} the new snapshot
 */
async function refresh() {
    const next = defaults();
    let rows = [];
    try {
        rows = (await db.query('SELECT key, value FROM app_settings')).rows;
    } catch (err) {
        console.error(`[Settings] Could not read app_settings, using .env values: ${err.message}`);
        snapshot = next;
        return snapshot;
    }

    for (const row of rows) {
        const field = FIELDS[row.key];
        if (!field) continue;
        try {
            const stored = field.secret ? cryptoService.decrypt(row.value) : row.value;
            next[field.group][field.name] = field.deserialize ? field.deserialize(stored) : field.parse(stored);
            next.overrides.push(row.key);
        } catch (err) {
            console.error(`[Settings] Ignoring stored "${row.key}": ${err.message}`);
        }
    }

    snapshot = next;
    return snapshot;
}

/**
 * Validate and store admin-supplied values. Only the keys present in `values` are written, and a saved value
 * always wins over .env: an empty SMTP host is stored as "mail off", not as a fallback to SMTP_HOST.
 * @param {object} values - flat map of FIELDS keys, e.g. { 'mail.host': 'relay.corp.example', 'reminders.days': '14,7,1' }
 * @param {string} actor - admin username, recorded in app_settings.updated_by
 * @returns {Promise<string[]>} the keys that were written or cleared
 */
async function save(values, actor) {
    const writes = [];

    for (const [key, raw] of Object.entries(values || {})) {
        const field = FIELDS[key];
        if (!field) throw invalid(`Unknown setting "${key}".`);
        // The unchanged placeholder means "keep the stored secret", so nothing is written for it
        if (field.secret && raw === SECRET_PLACEHOLDER) continue;
        const parsed = field.parse(raw);
        const stored = field.serialize ? field.serialize(parsed) : String(parsed);
        writes.push([key, field.secret ? cryptoService.encrypt(stored) : stored]);
    }

    const merged = previewMerge(writes);
    if (merged.reminders.enabled && !merged.mail.host) {
        throw invalid('Expiry reminders need an SMTP host.');
    }
    if (merged.mail.host && !merged.mail.from) {
        throw invalid('A From address is required when an SMTP host is set.');
    }

    for (const [key, value] of writes) {
        await db.query(
            `INSERT INTO app_settings (key, value, updated_by, updated_at) VALUES ($1, $2, $3, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = NOW()`,
            [key, value, actor || null]
        );
    }

    await refresh();
    return writes.map(([key]) => key);
}

// The effective values the writes would produce, so cross-field rules are checked before anything is stored
function previewMerge(writes) {
    const merged = {
        mail: { ...snapshot.mail },
        reminders: { ...snapshot.reminders },
    };
    for (const [key, value] of writes) {
        const field = FIELDS[key];
        const plain = field.secret ? cryptoService.decrypt(value) : value;
        merged[field.group][field.name] = field.deserialize ? field.deserialize(plain) : field.parse(plain);
    }
    return merged;
}

/**
 * What the admin panel shows: the effective values (SMTP password masked), which keys come from the database,
 * and the .env fallbacks, so an admin can see what clearing a field would restore.
 */
async function describe() {
    const settings = await refresh();
    const meta = (await db.query('SELECT key, updated_by, updated_at FROM app_settings ORDER BY updated_at DESC')).rows;
    return {
        mail: {
            host: settings.mail.host,
            port: settings.mail.port,
            secure: settings.mail.secure,
            user: settings.mail.user,
            password: settings.mail.password ? SECRET_PLACEHOLDER : '',
            from: settings.mail.from,
            portalName: settings.mail.portalName,
            portalUrl: settings.mail.portalUrl,
        },
        reminders: { ...settings.reminders, days: [...settings.reminders.days] },
        // From .env, shown read-only: these are not editable in the panel
        envDefaults: {
            host: config.mail.host,
            port: config.mail.port,
            from: config.mail.from,
            days: [...config.reminders.days],
            hour: config.reminders.hour,
            source: config.reminders.source,
            enabled: config.reminders.enabled,
        },
        secondaryDomain: config.ad.secondary ? config.ad.secondary.name : null,
        primaryDomain: config.ad.name,
        overrides: settings.overrides,
        updated: meta.map((row) => ({ key: row.key, updatedBy: row.updated_by, updatedAt: row.updated_at })),
    };
}

module.exports = { current, refresh, save, describe, SECRET_PLACEHOLDER, FIELDS };
