// Sends one test message through the SMTP settings in .env, or (--all) one sample of every mail the portal sends,
// built by the real templates with this server's settings. Samples are marked [Sample] and go to your address only.
// Usage (from the project folder): node scripts/send-test-mail.js someone@corp.example [--all]
const config = require('../server/config/default');
const mailService = require('../server/services/mailService');
const notificationService = require('../server/services/notificationService');

const DAY_MS = 24 * 60 * 60 * 1000;

function samples(to) {
    const username = to.split('@')[0];
    const person = { username, displayName: 'Sample User' };
    const alert = {
        ...person,
        ip: '192.0.2.10',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
    };
    const secondary = config.ad.secondary?.name;
    const synced = secondary ? { domain: secondary, status: 'synced' } : null;
    const reminderDomain = config.reminders.source === 'secondary' ? secondary : null;
    const reminder = (daysLeft) => notificationService.passwordExpiringMessage({
        ...person, daysLeft, domain: reminderDomain, expiresAt: new Date(Date.now() + daysLeft * DAY_MS),
    });

    const list = [
        ['alert after reset (authenticator app)', notificationService.passwordChangedMessage({ ...alert, method: 'totp', sync: synced })],
        ['alert after reset (security questions)', notificationService.passwordChangedMessage({ ...alert, method: 'security_questions', sync: synced })],
        ['alert after change (signed in)', notificationService.passwordChangedMessage({ ...alert, method: 'authenticated', sync: synced })],
    ];
    if (secondary) {
        list.push(['alert when the second domain was not updated', notificationService.passwordChangedMessage({
            ...alert, method: 'authenticated', sync: { domain: secondary, status: 'failed' },
        })]);
    }
    list.push(['security settings changed', notificationService.securityChangeMessage({
        ...alert, change: 'Text-message codes were set up for +91 •••••••• 10',
    })]);
    for (const days of [...config.reminders.days].sort((a, b) => b - a)) {
        list.push([`reminder ${days} day(s) before expiry`, reminder(days)]);
    }
    list.push(['password has expired', notificationService.passwordExpiredMessage({
        ...person, domain: reminderDomain, expiresAt: new Date(Date.now() - DAY_MS),
    })]);
    list.push(['admin notice: protected setting changed', notificationService.settingChangedMessage({
        actor: 'sample.admin', ip: alert.ip,
        changes: [{ label: 'Reset verification policy', value: 'Security questions and a one-time code (before: Security questions or a one-time code)' }],
    })]);
    return list;
}

async function main() {
    const to = process.argv[2];
    if (!to || !/^[^\s@]+@[^\s@]+$/.test(to)) {
        console.error('Usage: node scripts/send-test-mail.js <address> [--all]');
        process.exit(1);
    }
    if (!mailService.isEnabled()) {
        console.error('SMTP_HOST is not set in .env.');
        process.exit(1);
    }

    if (!process.argv.includes('--all')) {
        await mailService.send({
            to,
            ...notificationService.testMessage({
                host: config.mail.host, port: config.mail.port, from: config.mail.from, requestedBy: 'send-test-mail.js',
            }),
        });
        console.log(`Sent to ${to} via ${config.mail.host}:${config.mail.port} (from ${config.mail.from}).`);
        return;
    }

    for (const [label, message] of samples(to)) {
        await mailService.send({ to, ...message, subject: `[Sample] ${message.subject}` });
        console.log(`  sent: ${label}`);
    }
    console.log(`Samples sent to ${to} via ${config.mail.host}:${config.mail.port} (from ${config.mail.from}).`);
}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error(`Failed: ${err.message}`);
        process.exit(1);
    });
