// User notifications: "your password was changed" security alert, security-settings alerts, password expiry
// reminders, the admin notice for protected settings and the test mail.
// Every message is built by mailTemplate.render(): a plain-text and an HTML part with the same content. The only
// address in any mail is the portal's own (PORTAL_URL); a mail never contains a password or a code.
const config = require('../config/default');
const ldapService = require('./ldapService');
const mailService = require('./mailService');
const { render, describeDevice } = require('./mailTemplate');
const { logAudit } = require('../controllers/authController');

const VERIFIED_WITH = {
    security_questions: 'security questions',
    totp: 'authenticator app',
    sms: 'a code sent by SMS',
    'security_questions+totp': 'security questions and authenticator app',
    'security_questions+sms': 'security questions and a code sent by SMS',
};

const dateTime = new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
const dateOnly = new Intl.DateTimeFormat('en-GB', { dateStyle: 'full' });
const TIME_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

const WAS_THIS_YOU = 'If you made this change, no action is needed. If you did not make this change, contact IT immediately: '
    + 'someone else may know your password or be able to reset it.';

function portalName() {
    return config.mail.portalName;
}

function portalAction(label = 'Open the password portal') {
    return config.mail.portalUrl ? { label, url: config.mail.portalUrl } : null;
}

function greeting(displayName, username) {
    return `Hello ${displayName || username},`;
}

function when(date = new Date()) {
    return `${dateTime.format(date)} (${TIME_ZONE})`;
}

// Small print: why the reader got this mail, the phishing reminder, and that replies are not read
function userFooter(username) {
    return [
        `You are receiving this message because the account "${username}" uses ${portalName()} to change and reset its password.`,
        'Your IT team will never ask for your password by email, phone or chat.',
        'This message was sent automatically. Replies to it are not read; contact your IT service desk if you need help.',
    ];
}

function adminFooter() {
    return [
        `You are receiving this message because you are an administrator of ${portalName()}.`,
        'This message was sent automatically. Replies to it are not read.',
    ];
}

// Which domains received the new password, e.g. "Desktop and Mail" or "Desktop only (Mail was not updated)"
function updatedDomains(sync) {
    if (sync?.status === 'synced') return `${config.ad.name} and ${sync.domain}`;
    if (sync?.status === 'failed') return `${config.ad.name} only (${sync.domain} was not updated)`;
    return config.ad.name;
}

function passwordChangedMessage({ username, displayName, method, ip, userAgent, sync, when: at = new Date() }) {
    const isReset = method !== 'authenticated';
    const heading = isReset ? 'Your password was reset' : 'Your password was changed';
    const notices = [];
    if (sync?.status === 'failed') {
        notices.push({
            tone: 'warning',
            title: `Your ${sync.domain} password was not changed`,
            text: `The new password was set for ${config.ad.name}, but ${sync.domain} kept the old one. Use Forgot password `
                + 'in the portal to set a password that meets the requirements of both, or contact IT.',
        });
    }
    notices.push({ tone: 'neutral', title: 'Was this you?', text: WAS_THIS_YOU });

    return render({
        portalName: portalName(),
        subject: heading,
        heading,
        preheader: `The password for ${username} was ${isReset ? 'reset' : 'changed'} on ${dateTime.format(at)}.`,
        greeting: greeting(displayName, username),
        intro: [
            `The password for your account ${username} was ${isReset ? 'reset with Forgot password' : 'changed in the password portal'}. `
            + 'Here are the details so you can check that it was you.',
        ],
        details: [
            ['Account', username],
            ['Date and time', when(at)],
            ['How', isReset
                ? `Forgot password, verified with ${VERIFIED_WITH[method] || 'identity verification'}`
                : 'Signed in with the current password'],
            ['Updated in', updatedDomains(sync)],
            ['IP address', ip || 'Unknown'],
            ['Device', describeDevice(userAgent)],
        ],
        notices,
        action: portalAction(),
        footer: userFooter(username),
    });
}

/**
 * @param {object} p - { username, displayName, expiresAt, daysLeft, domain } domain: name of the domain whose
 *   password expires when it is not the sign-in domain
 */
function passwordExpiringMessage({ username, displayName, expiresAt, daysLeft, domain = null }) {
    const which = domain ? `${domain} password` : 'password';
    const subject = daysLeft === 1 ? `Your ${which} expires tomorrow` : `Your ${which} expires in ${daysLeft} days`;
    const whenText = daysLeft === 1 ? 'tomorrow' : `in ${daysLeft} days`;

    let steps;
    const outro = [];
    if (config.mail.portalUrl) {
        steps = [
            'Open the password portal with the button below.',
            'Sign in with your username and your current password.',
            'Choose Change Password and enter a new password that meets the rules shown on the page.',
        ];
        if (config.ad.secondary) {
            // Only the portal changes both domains, so Ctrl+Alt+Del is not suggested here
            outro.push(`Changing it in the portal updates both your ${config.ad.name} and ${config.ad.secondary.name} passwords.`);
        } else {
            outro.push('You can also press Ctrl+Alt+Del on a company computer and choose "Change a password".');
        }
    } else {
        steps = ['Press Ctrl+Alt+Del on your company computer.', 'Choose "Change a password" and follow the steps.'];
    }

    return render({
        portalName: portalName(),
        subject,
        heading: subject,
        preheader: `Change your ${which} before ${dateOnly.format(expiresAt)}.`,
        greeting: greeting(displayName, username),
        intro: [
            `The ${which} for your account ${username} expires ${whenText}, on ${dateOnly.format(expiresAt)}. `
            + 'After that you cannot sign in until it is reset, so please change it before then.',
        ],
        details: [
            ['Account', username],
            ['Password', domain ? `${domain} domain` : config.ad.name],
            ['Expires on', dateOnly.format(expiresAt)],
            ['Days left', String(daysLeft)],
        ],
        notices: daysLeft <= 3
            ? [{ tone: 'warning', title: 'Please change it today', text: 'It takes about a minute and avoids being locked out of your computer and mail.' }]
            : [],
        stepsTitle: 'How to change it',
        steps,
        action: portalAction(),
        outro,
        footer: userFooter(username),
    });
}

/**
 * After the password expired (reminders.expiredNotice).
 * @param {object} p - { username, displayName, expiresAt, domain }
 */
function passwordExpiredMessage({ username, displayName, expiresAt, domain = null }) {
    const which = domain ? `${domain} password` : 'password';
    const subject = `Your ${which} has expired`;
    const steps = config.mail.portalUrl
        ? [
            'Open the password portal with the button below.',
            'Choose Forgot password and enter your username.',
            'Confirm it is you with your security questions or one-time code.',
            'Set a new password that meets the rules shown on the page.',
        ]
        : [`Open ${portalName()} and choose Forgot password, or contact your IT service desk.`];

    return render({
        portalName: portalName(),
        subject,
        heading: subject,
        preheader: `Set a new ${which} with Forgot password.`,
        greeting: greeting(displayName, username),
        intro: [`The ${which} for your account ${username} expired on ${dateOnly.format(expiresAt)}. You can set a new one yourself.`],
        details: [
            ['Account', username],
            ['Password', domain ? `${domain} domain` : config.ad.name],
            ['Expired on', dateOnly.format(expiresAt)],
        ],
        stepsTitle: 'How to set a new password',
        steps,
        action: portalAction(),
        footer: userFooter(username),
    });
}

/**
 * "Your recovery settings changed": factor added or replaced, questions changed, enrolment reset, admin rights.
 * @param {object} p - { username, displayName, change, ip, userAgent, when }
 */
function securityChangeMessage({ username, displayName, change, ip, userAgent, when: at = new Date() }) {
    const subject = 'Your password reset settings changed';
    return render({
        portalName: portalName(),
        subject,
        heading: subject,
        preheader: `${change}.`,
        greeting: greeting(displayName, username),
        intro: [
            `There was a change to how your account ${username} can confirm its identity when the password is reset. `
            + 'Here are the details so you can check that it was you.',
        ],
        details: [
            ['What changed', change],
            ['Account', username],
            ['Date and time', when(at)],
            ['IP address', ip || 'Unknown'],
            ['Device', describeDevice(userAgent)],
        ],
        notices: [{ tone: 'neutral', title: 'Was this you?', text: WAS_THIS_YOU }],
        action: portalAction(),
        footer: userFooter(username),
    });
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

/**
 * Security alert after a change to the user's recovery settings. Never throws.
 * @param {object} p - { userId, username, change, req }
 */
async function sendSecurityChangeAlert({ userId, username, change, req }) {
    if (!mailService.isEnabled()) return;
    try {
        const user = await ldapService.findUser(username);
        if (!user?.mail) return;
        const message = securityChangeMessage({
            username, displayName: user.displayName, change, ip: req.ip, userAgent: req.headers?.['user-agent'],
        });
        await mailService.send({ to: user.mail, ...message });
        await logAudit(userId, username, 'notification', null, req, true, `Security alert (${change}) sent to ${user.mail}`);
    } catch (err) {
        console.error(`[Mail] Security alert for ${username} failed: ${err.message}`);
        await logAudit(userId, username, 'notification', null, req, false, `Security alert failed: ${err.message}`);
    }
}

/**
 * Body of the notice to portal admins after a protected setting changed.
 * @param {object} p - { actor, labels: string[], ip, when }
 */
function settingChangedMessage({ actor, labels, ip, when: at = new Date() }) {
    const subject = 'Portal security setting changed';
    return render({
        portalName: portalName(),
        subject,
        heading: subject,
        preheader: `${actor} changed: ${labels.join(', ')}.`,
        intro: [`${actor} changed security settings of ${portalName()}. These settings decide how users prove their identity and where reset codes are sent.`],
        details: [
            ['Changed by', actor],
            ['Settings', labels.join(', ')],
            ['Date and time', when(at)],
            ['IP address', ip || 'Unknown'],
        ],
        notices: [{
            tone: 'warning',
            title: 'Not agreed?',
            text: 'If this change was not agreed, review Administration > Verification and the audit log now.',
        }],
        action: portalAction('Open the portal'),
        footer: adminFooter(),
    });
}

/**
 * To every portal admin with a mail address after a protected setting changed. Never throws.
 * @param {object} p - { actor, labels: string[], req, recipients: string[] }
 */
async function sendSettingChangedNotice({ actor, labels, req, recipients }) {
    if (!mailService.isEnabled() || recipients.length === 0) return;
    try {
        await mailService.send({ to: recipients.join(', '), ...settingChangedMessage({ actor, labels, ip: req.ip }) });
        await logAudit(null, actor, 'notification', null, req, true, `Setting change notice sent to ${recipients.length} admin(s)`);
    } catch (err) {
        console.error(`[Mail] Setting change notice failed: ${err.message}`);
        await logAudit(null, actor, 'notification', null, req, false, `Setting change notice failed: ${err.message}`);
    }
}

/**
 * The test mail an admin sends from Administration -> Mail & Reminders.
 * @param {object} p - { host, port, from, requestedBy }
 * @returns {{subject, text, html}}
 */
function testMessage({ host, port, from, requestedBy }) {
    return render({
        portalName: portalName(),
        subject: `${portalName()}: test message`,
        heading: 'Test message',
        preheader: 'Outgoing mail from the password portal works.',
        intro: ['This test message confirms that the password portal can send mail. Password alerts and expiry reminders use the same settings.'],
        details: [
            ['Relay', `${host}:${port}`],
            ['From address', from],
            ['Requested by', requestedBy],
            ['Sent', when()],
        ],
        notices: [{ tone: 'success', text: 'If you can read this, mail delivery works. Check that it arrived in the inbox, not in junk mail.' }],
        action: portalAction('Open the portal'),
        footer: adminFooter(),
    });
}

module.exports = {
    passwordChangedMessage,
    passwordExpiringMessage,
    passwordExpiredMessage,
    securityChangeMessage,
    settingChangedMessage,
    sendPasswordChangedAlert,
    sendSecurityChangeAlert,
    sendSettingChangedNotice,
    testMessage,
};
