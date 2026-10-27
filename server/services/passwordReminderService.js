// Daily password expiry reminders (PASSWORD_REMINDERS=true) to every enabled first-domain user with a mail address.
// The expiry comes from PASSWORD_REMINDER_SOURCE: the first domain, or the second one when only it expires passwords
// (then only users the sync would update and who can sign in to the portal are reminded).
// Each stage (e.g. 14 days before expiry, then daily over the last week) is mailed once per expiry date; password_reminders records
// what was sent, so restarts and repeated runs never send duplicates, and a new password starts a new cycle.
const config = require('../config/default');
const db = require('../config/db');
const settingsService = require('./settingsService');
const ldapService = require('./ldapService');
const mailService = require('./mailService');
const notificationService = require('./notificationService');
const passwordSyncService = require('./passwordSyncService');
const { logAudit } = require('../controllers/authController');

const DAY_MS = 24 * 60 * 60 * 1000;
const UAC_ACCOUNT_DISABLED = 2;
const CHECK_INTERVAL_MS = 60 * 60 * 1000;
const NO_REQUEST = { headers: {} };

// Most urgent stage reached: 10 days left with stages 14,7,6,5,4,3,2,1 → 14; 5 days left → 5
function currentStage(daysLeft, days = settingsService.current().reminders.days) {
    const reached = days.filter((d) => daysLeft <= d);
    return reached.length ? Math.min(...reached) : null;
}

/**
 * For a second-domain expiry: the first-domain account that receives the reminder, or null when a portal
 * change would not help (the sync refuses that account, or the user cannot sign in to the portal).
 */
async function signInAccount(entry) {
    const refusal = passwordSyncService.refusalReason({ ...entry, sAMAccountName: entry.username });
    if (refusal) return { skip: `${ldapService.secondary.name}: ${refusal}` };
    const user = await ldapService.findUser(entry.username);
    if (!user) return { skip: `no ${config.ad.name} account` };
    if ((parseInt(user.userAccountControl, 10) & UAC_ACCOUNT_DISABLED) !== 0) return { skip: `${config.ad.name} account disabled` };
    if (!user.mail) return { skip: `no mail address in ${config.ad.name}` };
    return { user: { username: user.sAMAccountName, displayName: user.displayName || entry.displayName, mail: user.mail } };
}

function countSkip(result, reason) {
    result.skipped[reason] = (result.skipped[reason] || 0) + 1;
}

/**
 * One pass over the directory.
 * @param {object} [options] - { now, dryRun } dryRun: report who would get a mail, send nothing
 * @returns {Promise<{checked: number, due: Array, sent: number, failed: number}>}
 */
async function runOnce({ now = new Date(), dryRun = false } = {}) {
    // Picks up an admin change (stages, source) made since the last run
    const { days, source: expirySource } = (await settingsService.refresh()).reminders;
    const fromSecondary = expirySource === 'secondary';
    const source = fromSecondary ? ldapService.secondary : ldapService;
    const entries = await source.listPasswordExpiries();
    // withExpiry/expired: every account the source reports; inWindow: has reached a stage;
    // expiring: in the window and not yet reminded; skipped: reason → count (second-domain source)
    const result = {
        checked: entries.length, withExpiry: 0, expired: 0, inWindow: 0, reminded: [],
        expiring: 0, skipped: {}, due: [], sent: 0, failed: 0,
    };

    for (const entry of entries) {
        if (!entry.expiresAt) continue;
        result.withExpiry++;
        const daysLeft = Math.ceil((entry.expiresAt - now) / DAY_MS);
        if (daysLeft <= 0) {
            result.expired++;
            continue;
        }
        const stage = currentStage(daysLeft, days);
        if (stage === null) continue;
        result.inWindow++;

        const already = await db.query(
            'SELECT sent_at FROM password_reminders WHERE username = $1 AND expires_at = $2 AND days_before = $3',
            [entry.username.toLowerCase(), entry.expiresAt, stage]
        );
        if (already.rows.length) {
            // Already mailed for this stage: reported so a preview still shows who is covered
            result.reminded.push({
                username: entry.username, daysLeft, stage, expiresAt: entry.expiresAt, sentAt: already.rows[0].sent_at,
            });
            continue;
        }

        result.expiring++;
        let user = entry;
        if (fromSecondary) {
            const account = await signInAccount(entry);
            if (account.skip) {
                countSkip(result, account.skip);
                continue;
            }
            user = account.user;
        }
        result.due.push({ username: user.username, mail: user.mail, daysLeft, stage, expiresAt: entry.expiresAt });
        if (dryRun) continue;

        // Claimed before sending, so two runs can never mail the same stage twice
        const claim = await db.query(
            `INSERT INTO password_reminders (username, expires_at, days_before) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING RETURNING 1`,
            [entry.username.toLowerCase(), entry.expiresAt, stage]
        );
        if (!claim.rows.length) continue;

        try {
            await mailService.send({
                to: user.mail,
                ...notificationService.passwordExpiringMessage({
                    ...user,
                    expiresAt: entry.expiresAt,
                    daysLeft,
                    domain: fromSecondary ? ldapService.secondary.name : null,
                }),
            });
            result.sent++;
            await logAudit(null, user.username, 'password_reminder', null, NO_REQUEST, true,
                `Expires in ${daysLeft} day(s); reminder sent to ${user.mail}`);
        } catch (err) {
            // Released so the next run retries
            await db.query(
                'DELETE FROM password_reminders WHERE username = $1 AND expires_at = $2 AND days_before = $3',
                [entry.username.toLowerCase(), entry.expiresAt, stage]
            );
            result.failed++;
            await logAudit(null, user.username, 'password_reminder', null, NO_REQUEST, false, `Reminder failed: ${err.message}`);
        }
    }

    if (!dryRun) await db.query("DELETE FROM password_reminders WHERE expires_at < NOW() - INTERVAL '30 days'");
    return result;
}

/**
 * Checks hourly and runs once per day from the configured hour (local time). The timer always runs: whether
 * reminders are on, from which hour, and with which stages is read from the settings on every tick, so an
 * admin can switch them on in the panel without a restart.
 * @returns {NodeJS.Timeout} interval to clear on shutdown
 */
function start() {
    let lastRunDay = null;

    const tick = async () => {
        const { enabled, hour } = (await settingsService.refresh()).reminders;
        if (!enabled || !mailService.isEnabled()) return;
        const now = new Date();
        const today = now.toDateString();
        if (now.getHours() < hour || lastRunDay === today) return;
        lastRunDay = today;
        try {
            const { checked, sent, failed } = await runOnce({ now });
            console.log(`[Reminders] ${checked} account(s) checked, ${sent} reminder(s) sent, ${failed} failed`);
        } catch (err) {
            lastRunDay = null; // directory or database unavailable: retry at the next check
            console.error(`[Reminders] Run failed: ${err.message}`);
        }
    };

    setTimeout(tick, 60 * 1000).unref();
    const timer = setInterval(tick, CHECK_INTERVAL_MS);
    timer.unref();
    return timer;
}

module.exports = { runOnce, start, currentStage };
