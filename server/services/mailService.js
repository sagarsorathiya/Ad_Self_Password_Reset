// Outgoing mail through the configured SMTP relay (plain text plus an HTML alternative, see mailTemplate.js).
// The server, port and credentials come from settingsService, so an admin change applies without a restart:
// the transport is rebuilt as soon as one of those values differs from the one it was created with.
const nodemailer = require('nodemailer');
const config = require('../config/default');
const settingsService = require('./settingsService');

let transport = null;
let transportKey = null;
let stubbed = false;

function mailSettings() {
    return settingsService.current().mail;
}

function isEnabled() {
    return Boolean(mailSettings().host);
}

function getTransport() {
    const { host, port, secure, user, password } = mailSettings();
    const key = JSON.stringify([host, port, secure, user, password]);
    if (!stubbed && (!transport || transportKey !== key)) {
        transport = nodemailer.createTransport({
            host,
            port,
            secure,
            auth: user ? { user, pass: password } : undefined,
            tls: config.mail.tlsOptions,
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 20000,
        });
        transportKey = key;
    }
    return transport;
}

/**
 * The sender as mail clients show it. A bare address ("portal@corp.example") gets the portal name as its display
 * name, so inboxes show "Password Portal" instead of an unknown address - one of the things filters and users
 * judge a mail by. A value that already has a name ("IT Desk <it@corp.example>") is used as it is.
 */
function fromAddress() {
    const from = String(mailSettings().from || '').trim();
    if (!from || from.includes('<')) return from;
    return { name: mailSettings().portalName || config.mail.portalName, address: from };
}

/**
 * @param {{to: string, subject: string, text: string, html?: string}} message
 *   html: the HTML part; sent as multipart/alternative together with the text part
 */
async function send({ to, subject, text, html }) {
    if (!isEnabled()) throw new Error('Mail is not configured (SMTP host)');
    await getTransport().sendMail({
        from: fromAddress(),
        to,
        subject,
        text,
        html: html || undefined,
        headers: {
            // RFC 3834: machine-generated, so auto-responders (out-of-office) do not answer it
            'Auto-Submitted': 'auto-generated',
            'X-Auto-Response-Suppress': 'All',
        },
    });
}

module.exports = {
    isEnabled,
    send,
    // Tests only: replace the SMTP transport with a stub ({ sendMail(message) })
    setTransport: (stub) => {
        transport = stub;
        stubbed = Boolean(stub);
        transportKey = null;
    },
};
