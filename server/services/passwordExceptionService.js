const db = require('../config/db');

const MATCH_TYPES = ['contains', 'exact'];

// Common character substitutions (P@ssw0rd), so "password" also blocks its look-alikes
const LEET = { '@': 'a', 4: 'a', 3: 'e', 0: 'o', $: 's', 5: 's', 7: 't', '!': 'i', '|': 'i' };
const normalizers = [
    (s) => s.toLowerCase(),
    (s) => s.toLowerCase().replace(/[@430$57!|]/g, (c) => LEET[c]).replace(/1/g, 'i'),
    (s) => s.toLowerCase().replace(/[@430$57!|]/g, (c) => LEET[c]).replace(/1/g, 'l'),
];

function matches(password, term, matchType) {
    return normalizers.some((normalize) => {
        const pw = normalize(password);
        const t = normalize(term);
        return matchType === 'exact' ? pw === t : pw.includes(t);
    });
}

/**
 * Returns the first active exception the password violates, or null.
 * Matching happens in-process so the candidate password is never sent to the database.
 */
async function findViolation(password) {
    const result = await db.query(
        'SELECT term, match_type FROM password_exceptions WHERE is_active = TRUE ORDER BY LENGTH(term) DESC'
    );
    return result.rows.find((row) => matches(password, row.term, row.match_type)) || null;
}

module.exports = { MATCH_TYPES, findViolation, matches };
