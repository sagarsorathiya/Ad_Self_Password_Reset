// Explains WHY a password does not meet the AD password policy.
//
// AD itself only answers "constraint violation" (0000052D) for every policy rule, and ldapjs 3.0.7 drops even that
// text. So the portal reads the effective policy (the domain policy, or the fine-grained policy (PSO) that applies to
// the user) and checks the rules it can check itself before AD is asked:
//   - minimum length
//   - complexity: 3 of 5 character categories, no sAMAccountName, no display-name part of 3+ characters
// Two rules can only be explained after AD refused the password: the minimum password age (from pwdLastSet) and the
// password history (AD never reveals old passwords).
//
// Everything here except forUser()/domainRules() is pure and unit-tested; those two read AD through ldapService and
// fall back to null when the policy cannot be read (AD still enforces it then, and the generic message is used).
const ldapService = require('./ldapService');
const { fileTimeToDate } = require('./adTime');

const DAY_MS = 24 * 60 * 60 * 1000;
const DOMAIN_CACHE_MS = 15 * 60 * 1000;
const dateTime = new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' });

/**
 * AD intervals (minPwdAge, msDS-MinimumPasswordAge) are negative counts of 100-nanosecond units.
 * @returns {number} days (0 when unset)
 */
function intervalToDays(value) {
    const n = Number(value);
    if (!Number.isFinite(n) || n === 0) return 0;
    return Math.abs(n) / (DAY_MS * 10000);
}

/**
 * Normalise raw attributes from the domain root or a PSO into one shape.
 * @param {object} raw - domain: minPwdLength, pwdProperties, pwdHistoryLength, minPwdAge
 *                       PSO: msDS-MinimumPasswordLength, msDS-PasswordComplexityEnabled, msDS-PasswordHistoryLength, msDS-MinimumPasswordAge
 * @param {'domain'|'fine-grained'} source
 */
function normalizePolicy(raw, source) {
    if (!raw) return null;
    if (source === 'fine-grained') {
        return {
            source,
            minLength: parseInt(raw['msDS-MinimumPasswordLength'], 10) || 0,
            complexity: String(raw['msDS-PasswordComplexityEnabled']).toUpperCase() === 'TRUE',
            historyLength: parseInt(raw['msDS-PasswordHistoryLength'], 10) || 0,
            minAgeDays: intervalToDays(raw['msDS-MinimumPasswordAge']),
        };
    }
    return {
        source,
        minLength: parseInt(raw.minPwdLength, 10) || 0,
        // DOMAIN_PASSWORD_COMPLEX = bit 1 of pwdProperties
        complexity: (parseInt(raw.pwdProperties, 10) & 1) === 1,
        historyLength: parseInt(raw.pwdHistoryLength, 10) || 0,
        minAgeDays: intervalToDays(raw.minPwdAge),
    };
}

// AD splits the display name on these characters and ignores parts shorter than 3 characters
function displayNameParts(displayName) {
    return String(displayName || '')
        .split(/[,.\-_#\t ]+/)
        .filter((part) => part.length >= 3);
}

const CATEGORY_TESTS = [
    ['uppercase letters', (ch) => /\p{Lu}/u.test(ch)],
    ['lowercase letters', (ch) => /\p{Ll}/u.test(ch)],
    ['numbers', (ch) => /[0-9]/.test(ch)],
    ['symbols', (ch) => !/[\p{L}\p{N}]/u.test(ch)],
    ['other letters', (ch) => /\p{L}/u.test(ch) && !/[\p{Lu}\p{Ll}]/u.test(ch)],
];

function categoriesIn(password) {
    const chars = [...String(password)];
    return CATEGORY_TESTS.filter(([, test]) => chars.some(test)).map(([name]) => name);
}

function listWords(words) {
    if (words.length <= 1) return words.join('');
    return `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
}

/**
 * The rules the portal can check itself. Order: length, character types, username, name parts.
 * @param {string} password
 * @param {object} policy - normalizePolicy() result
 * @param {object} identity - { username, displayName }
 * @returns {Array<{rule: string, message: string}>} empty = no problem found
 */
function checkAgainstPolicy(password, policy, { username, displayName } = {}) {
    if (!policy) return [];
    const problems = [];
    const length = [...String(password)].length;

    if (policy.minLength && length < policy.minLength) {
        problems.push({
            rule: 'length',
            message: `Use at least ${policy.minLength} characters (this one has ${length}).`,
        });
    }

    if (policy.complexity) {
        const found = categoriesIn(password);
        if (found.length < 3) {
            problems.push({
                rule: 'complexity',
                message: 'Use at least 3 of these: uppercase letters, lowercase letters, numbers, symbols '
                    + `(it has ${found.length ? `only ${listWords(found)}` : 'none of them'}).`,
            });
        }
        const lower = String(password).toLowerCase();
        const name = String(username || '');
        const hasUsername = name.length >= 3 && lower.includes(name.toLowerCase());
        if (hasUsername) {
            problems.push({ rule: 'username', message: `It must not contain your username (${name}).` });
        }
        // A name part inside the username ("Smith" in "jsmith") is already covered by the username message
        const parts = displayNameParts(displayName)
            .filter((part) => lower.includes(part.toLowerCase()))
            .filter((part) => !(hasUsername && name.toLowerCase().includes(part.toLowerCase())));
        if (parts.length) {
            problems.push({
                rule: 'name',
                message: `It must not contain ${parts.length === 1 ? 'a part' : 'parts'} of your name (${listWords(parts)}).`,
            });
        }
    }
    return problems;
}

/**
 * After AD refused a password that passed checkAgainstPolicy(): the most likely reason.
 * @param {object} p
 * @param {object|null} p.policy
 * @param {'change'|'reset'} p.mode - the minimum age applies to a change by the user, not to an admin reset
 * @param {string} [p.pwdLastSet] - AD FILETIME of the last password change
 * @param {Date} [p.now]
 * @returns {Array<{rule: string, message: string}>}
 */
function explainRejection({ policy, mode, pwdLastSet, now = new Date() }) {
    if (!policy) return [];
    if (mode === 'change' && policy.minAgeDays > 0) {
        const last = fileTimeToDate(pwdLastSet);
        if (last) {
            const earliest = new Date(last.getTime() + policy.minAgeDays * DAY_MS);
            if (earliest > now) {
                const days = Number.isInteger(policy.minAgeDays) ? policy.minAgeDays : policy.minAgeDays.toFixed(1);
                return [{
                    rule: 'min-age',
                    message: `Your password was changed on ${dateTime.format(last)}, and the policy allows a new change `
                        + `only after ${days} day${days === 1 ? '' : 's'}. You can change it again from ${dateTime.format(earliest)}. `
                        + 'If you need it sooner, contact IT.',
                }];
            }
        }
    }
    if (policy.historyLength > 0) {
        return [{
            rule: 'history',
            message: `It matches one of your last ${policy.historyLength} passwords. Choose a password you have not used before.`,
        }];
    }
    return [];
}

/** One message for the response: a lead sentence the UI shows above the list. */
function summarize(problems) {
    return problems.length === 1
        ? `The new password does not meet the domain password policy: ${problems[0].message}`
        : 'The new password does not meet the domain password policy. Please fix the points below.';
}

// ---- Reading the policy from AD ----

let domainCache = { at: 0, value: null };

async function domainPolicy() {
    if (domainCache.value && Date.now() - domainCache.at < DOMAIN_CACHE_MS) return domainCache.value;
    const raw = await ldapService.getDomainPasswordPolicy();
    const value = normalizePolicy(raw, 'domain');
    domainCache = { at: Date.now(), value };
    return value;
}

/**
 * The policy that applies to this user: their fine-grained policy (PSO) if one applies, else the domain policy.
 * @param {object} adUser - findUser() entry (dn)
 * @returns {Promise<object|null>} null when the policy cannot be read; AD still enforces it then
 */
async function forUser(adUser) {
    try {
        const pso = adUser?.dn ? await ldapService.getResultantPasswordPolicy(adUser.dn).catch(() => null) : null;
        if (pso) return normalizePolicy(pso, 'fine-grained');
        return await domainPolicy();
    } catch (err) {
        console.warn(`[Policy] Could not read the password policy: ${err.message}`);
        return null;
    }
}

/** The domain policy for the unauthenticated rules endpoint, or null. */
async function domainRules() {
    try {
        return await domainPolicy();
    } catch {
        return null;
    }
}

module.exports = {
    intervalToDays,
    normalizePolicy,
    checkAgainstPolicy,
    explainRejection,
    summarize,
    forUser,
    domainRules,
    // Tests only
    resetCache: () => { domainCache = { at: 0, value: null }; },
};
