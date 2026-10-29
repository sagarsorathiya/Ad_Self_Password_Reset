// Outgoing SMS through a generic HTTP gateway. The URL, body and headers are templates, so any provider
// that accepts an HTTP request (MSG91, Kaleyra, TextLocal, an on-premise SMPP-to-HTTP box, ...) works
// without code changes. Settings come from settingsService, so an admin change applies without a restart.
//
// Placeholders, substituted in the URL, body, headers and message template:
//   {mobile}       E.164 number with the leading +,  e.g. +919876543210
//   {mobile_plain} the same number without the +,    e.g. 919876543210
//   {message}      the finished message text
//   {otp}          the one-time code on its own
//   {sender}       the configured sender ID
//   {portal}       the portal name
//   {minutes}      how long the code stays valid
// Values are escaped for where they are used (percent-encoded in a URL, JSON-escaped in a JSON body),
// so a number or message can never break out of the template.
const settingsService = require('./settingsService');

const REQUEST_TIMEOUT_MS = 15000;
// Gateways answer with the provider's message id or an error text; keep enough to diagnose, not a whole page
const MAX_RESPONSE_CHARS = 300;

let sender = null;

function smsSettings() {
    return settingsService.current().sms;
}

function isEnabled() {
    return Boolean(smsSettings().url);
}

/**
 * Replace {placeholders} in a template.
 * @param {string} template
 * @param {object} vars - placeholder name -> value
 * @param {'url'|'json'|'raw'} context - how each value is escaped
 */
function render(template, vars, context) {
    const escape = {
        url: encodeURIComponent,
        // Strip the surrounding quotes JSON.stringify adds: the template supplies them
        json: (value) => JSON.stringify(String(value)).slice(1, -1),
        raw: String,
    }[context];

    return String(template || '').replace(/\{(\w+)\}/g, (match, name) => (
        Object.prototype.hasOwnProperty.call(vars, name) ? escape(vars[name]) : match
    ));
}

// "X-API-Key: abc\nAccept: application/json" -> { 'X-API-Key': 'abc', Accept: 'application/json' }
function parseHeaders(raw, vars) {
    const headers = {};
    for (const line of String(raw || '').split(/\r?\n/)) {
        const text = line.trim();
        if (!text || text.startsWith('#')) continue;
        const separator = text.indexOf(':');
        if (separator < 1) continue;
        headers[text.slice(0, separator).trim()] = render(text.slice(separator + 1).trim(), vars, 'raw');
    }
    return headers;
}

/**
 * Build the message text for a one-time code.
 * @param {string} code
 * @param {number} minutes - validity of the code
 */
function buildMessage(code, minutes) {
    const settings = smsSettings();
    return render(settings.messageTemplate, {
        otp: code,
        minutes,
        portal: settingsService.current().mail.portalName,
        sender: settings.senderId,
    }, 'raw');
}

/**
 * Send one SMS. Throws with a short, gateway-supplied reason when the request fails.
 * @param {{to: string, text: string}} message - `to` is an E.164 number (+countrycode...)
 */
async function send({ to, text }) {
    if (!isEnabled()) throw new Error('SMS is not configured (gateway URL)');
    const settings = smsSettings();

    const vars = {
        mobile: to,
        mobile_plain: to.replace(/^\+/, ''),
        message: text,
        sender: settings.senderId,
        portal: settingsService.current().mail.portalName,
    };

    const url = render(settings.url, vars, 'url');
    const headers = parseHeaders(settings.headers, vars);
    let body;

    if (settings.method === 'POST' && settings.bodyType !== 'none') {
        if (settings.bodyType === 'json') {
            body = render(settings.bodyTemplate, vars, 'json');
            headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        } else {
            body = render(settings.bodyTemplate, vars, 'url');
            headers['Content-Type'] = headers['Content-Type'] || 'application/x-www-form-urlencoded';
        }
    }

    if (sender) return sender({ url, method: settings.method, headers, body, to, text });

    let response;
    try {
        response = await fetch(url, {
            method: settings.method,
            headers,
            body,
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
    } catch (err) {
        // A DNS name or timeout is safe to show an admin; it never contains the message or the code
        throw new Error(`SMS gateway unreachable: ${err.message}`);
    }

    const answer = (await response.text().catch(() => '')).trim().slice(0, MAX_RESPONSE_CHARS);
    if (!response.ok) {
        throw new Error(`SMS gateway returned HTTP ${response.status}${answer ? `: ${answer}` : ''}`);
    }
    if (settings.successText && !answer.includes(settings.successText)) {
        throw new Error(`SMS gateway did not confirm delivery: ${answer || '(empty response)'}`);
    }
    return { response: answer };
}

/**
 * What the admin panel shows about the configured gateway (never the headers: they hold the API key).
 */
function describeGateway() {
    const settings = smsSettings();
    return {
        configured: Boolean(settings.url),
        method: settings.method,
        // Host only, so a URL with an API key in the query string is not echoed back
        host: settings.url ? safeHost(settings.url) : '',
    };
}

function safeHost(url) {
    try {
        return new URL(url.replace(/\{\w+\}/g, 'x')).host;
    } catch {
        return '(invalid URL)';
    }
}

module.exports = {
    isEnabled,
    send,
    buildMessage,
    describeGateway,
    render,
    parseHeaders,
    timeoutMs: REQUEST_TIMEOUT_MS,
    // Tests only: replace the HTTP call with a stub (request) => any
    setSender: (stub) => { sender = stub; },
};
