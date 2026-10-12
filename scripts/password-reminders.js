// Shows who would get a password expiry reminder now (dry run, default), or sends them (--send).
// Usage (from the project folder): node scripts/password-reminders.js [--send]
const config = require('../server/config/default');
const db = require('../server/config/db');
const mailService = require('../server/services/mailService');
const passwordReminderService = require('../server/services/passwordReminderService');

async function main() {
    const send = process.argv.includes('--send');
    if (send && !mailService.isEnabled()) throw new Error('SMTP_HOST is not set in .env.');
    console.log(`Stages: ${config.reminders.days.join(', ')} days before expiry${send ? '' : ' (dry run, nothing is sent)'}`);

    const source = config.reminders.source === 'secondary' ? config.ad.secondary.name : config.ad.name;
    const result = await passwordReminderService.runOnce({ dryRun: !send });
    for (const u of result.due) {
        console.log(`  ${u.username.padEnd(24)} ${String(u.daysLeft).padStart(3)} day(s)  ${u.mail}`);
    }
    console.log('');
    console.log(`${result.checked} ${source} account(s) checked (expiry read from ${source})`);
    console.log(`${result.expiring} expire within ${Math.max(...config.reminders.days)} days and are not yet reminded`);
    for (const [reason, count] of Object.entries(result.skipped)) {
        console.log(`  - ${String(count).padStart(4)} skipped: ${reason}`);
    }
    console.log(`${result.due.length} due (reminder goes to the ${config.ad.name} mail address)`
        + (send ? `: ${result.sent} sent, ${result.failed} failed` : ''));
}

main()
    .catch((err) => {
        console.error(`Failed: ${err.message}`);
        process.exitCode = 1;
    })
    .finally(() => db.pool.end());
