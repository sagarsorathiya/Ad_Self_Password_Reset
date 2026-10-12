// User notifications: "your password was changed" security alert and password expiry reminders.
// Plain text only; the only address in a mail is the portal's own (PORTAL_URL).
const config = require('../config/default');
const ldapService = require('./ldapService');
const mailService = require('./mailService');
const { logAudit } = require('../controllers/authController');

const VERIFIED_WITH = {
    security_questions: 'security questions',
    totp: 'authenticator app',
    'security_questions+totp': 'security questions and authenticator app',
};

const dateTime = new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
const dateOnly = new Intl.DateTimeFormat('en-GB', { dateStyle: 'full' });
const TIME_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

const FOOTER = [
    '',
    'Never share your password. IT will never ask for it by email or phone.',
    `This is an automatic message from ${config.mail.portalName}; please do not reply.`,
];

function portalLine() {
    return config.mail.portalUrl ? ['', `Password portal: ${config.mail.portalUrl}`] : [];
}

function greeting(displayName, username) {
    return `Hello ${displayName || username},`;
}

// Which domains received the new password, e.g. "Desktop, Mail" or "Desktop (Mail: NOT updated)"
function updatedDomains(sync) {
    if (!sync) return config.ad.name;
    if (sync.status === 'synced') return `${config.ad.name}, ${sync.domain}`;
    if (sync.status === 'failed') return `${config.ad.name} (${sync.domain}: NOT updated)`;
    return config.ad.name;
}

function passwordChangedMessage({ username, displayName, method, ip, userAgent, sync, when = new Date() }) {
    const isReset = method !== 'authenticated';
    const how = isReset
        ? `reset with "Forgot password" (verified with: ${VERIFIED_WITH[method] || 'identity verification'})`
        : 'changed by signing in to the portal with the current password';
    return {
        subject: isReset ? 'Your password was reset' : 'Your password was changed',
        text: [
            greeting(displayName, username),
            '',
            `The password for your account "${username}" was ${how}.`,
            '',
            `When:      ${dateTime.format(when)} (${TIME_ZONE})`,
            `From IP:   ${ip || 'unknown'}`,
            `Browser:   ${String(userAgent || 'unknown').slice(0, 200)}`,
            `Updated:   ${updatedDomains(sync)}`,
            '',
            'If this was you, no action is needed.',
            'If this was NOT you, contact IT immediately: someone else may have access to your account.',
            ...portalLine(),
            ...FOOTER,
        ].join('\n'),
    };
}

/**
 * @param {object} p - { username, displayName, expiresAt, daysLeft, domain } domain: name of the domain whose
 *   password expires when it is not the sign-in domain
 */
function passwordExpiringMessage({ username, displayName, expiresAt, daysLeft, domain = null }) {
    const when = daysLeft === 1 ? 'tomorrow' : `in ${daysLeft} days`;
    const which = domain ? `${domain} password` : 'password';
    const lines = [
        greeting(displayName, username),
        '',
        `The ${which} for your account "${username}" expires ${when}, on ${dateOnly.format(expiresAt)}.`,
        'Please change it before then; after it expires you cannot sign in until it is reset.',
        '',
    ];
    const portal = config.mail.portalUrl
        ? `${config.mail.portalUrl} (sign in, then choose Change Password)`
        : config.mail.portalName;
    if (config.ad.secondary) {
        // Only the portal changes both domains, so Ctrl+Alt+Del is not suggested here
        lines.push(`Change it at ${portal}.`);
        lines.push(`This updates both your ${config.ad.name} and ${config.ad.secondary.name} passwords.`);
    } else if (config.mail.portalUrl) {
        lines.push(`Change it at ${portal},`);
        lines.push('or press Ctrl+Alt+Del on your computer and choose "Change a password".');
    } else {
        lines.push('To change it, press Ctrl+Alt+Del on your computer and choose "Change a password".');
    }
    return {
        subject: daysLeft === 1 ? `Your ${which} expires tomorrow` : `Your ${which} expires in ${daysLeft} days`,
        text: [...lines, ...FOOTER].join('\n'),
    };
}

/**
 * Security alert after a successful change or reset. Never throws: the password has already changed.
 * The address is the mail attribute of the first-domain (sign-in) account.
 * @param {object} p - { userId, username, method, req, sync, adUser? }
 */
async function sendPasswordChangedAlert({ userId, username, method, req, sync, adUser }) {
    if (!mailService.isEnabled()) return;
    try {
        const user = adUser || await ldapService.findUser(username);
        if (!user?.mail) {
            await logAudit(userId, username, 'notification', method, req, true, 'Password alert skipped: no mail address in AD');
            return;
        }
        const message = passwordChangedMessage({
            username,
            displayName: user.displayName,
            method,
            ip: req.ip,
            userAgent: req.headers?.['user-agent'],
            sync,
        });
        await mailService.send({ to: user.mail, ...message });
        await logAudit(userId, username, 'notification', method, req, true, `Password alert sent to ${user.mail}`);
    } catch (err) {
        console.error(`[Mail] Password alert for ${username} failed: ${err.message}`);
        await logAudit(userId, username, 'notification', method, req, false, `Password alert failed: ${err.message}`);
    }
}

module.exports = { passwordChangedMessage, passwordExpiringMessage, sendPasswordChangedAlert };
