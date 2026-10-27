// Outgoing mail through the configured SMTP relay (plain-text messages only).
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
 * @param {{to: string, subject: string, text: string}} message
 */
async function send({ to, subject, text }) {
    if (!isEnabled()) throw new Error('Mail is not configured (SMTP host)');
    await getTransport().sendMail({ from: mailSettings().from, to, subject, text });
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
