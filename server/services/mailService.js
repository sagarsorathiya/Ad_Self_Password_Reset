// Outgoing mail through the configured SMTP relay (plain-text messages only).
const nodemailer = require('nodemailer');
const config = require('../config/default');

let transport = null;

function isEnabled() {
    return Boolean(config.mail.host);
}

function getTransport() {
    if (!transport) {
        const { host, port, secure, user, password, tlsOptions } = config.mail;
        transport = nodemailer.createTransport({
            host,
            port,
            secure,
            auth: user ? { user, pass: password } : undefined,
            tls: tlsOptions,
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 20000,
        });
    }
    return transport;
}

/**
 * @param {{to: string, subject: string, text: string}} message
 */
async function send({ to, subject, text }) {
    if (!isEnabled()) throw new Error('Mail is not configured (SMTP_HOST)');
    await getTransport().sendMail({ from: config.mail.from, to, subject, text });
}

module.exports = {
    isEnabled,
    send,
    // Tests only: replace the SMTP transport with a stub ({ sendMail(message) })
    setTransport: (stub) => { transport = stub; },
};
