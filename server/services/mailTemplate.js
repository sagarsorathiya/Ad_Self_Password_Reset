// Layout for every mail the portal sends: one structured description -> a plain-text part and an HTML part
// with the same content (multipart/alternative, which mail filters expect from a legitimate sender).
// Pure (no I/O), so it is unit-tested.
//
// Deliberate choices, each one because filters or users treat the opposite as a sign of spam or phishing:
//   - no images, web fonts, scripts or external resources; every style is inline (mail clients drop <style>)
//   - the portal address is the only link, and its visible text is the address itself, never "click here"
//   - no capitals for emphasis, no exclamation marks, no urgency words in subjects
//   - the HTML and the text part say the same thing; every dynamic value is HTML-escaped

const COLORS = {
    page: '#f3f4f6',
    surface: '#ffffff',
    border: '#dde2e8',
    header: '#26221f',
    accent: '#f5b400',
    primary: '#c2410c',
    text: '#1d2733',
    secondary: '#4a5563',
    muted: '#6b7584',
    labelBg: '#f8f9fb',
    notice: {
        info: { bg: '#fff8eb', border: '#f5d9a8', text: '#7c2d12' },
        neutral: { bg: '#f8f9fb', border: '#c3cad3', text: '#1d2733' },
        warning: { bg: '#fdf4e3', border: '#f1d49b', text: '#7a4800' },
        danger: { bg: '#fdeceb', border: '#f3b8b3', text: '#8a1c13' },
        success: { bg: '#e8f5ec', border: '#b9e0c6', text: '#14532d' },
    },
};
const FONT = "'Segoe UI', Arial, Helvetica, sans-serif";

function esc(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * "Chrome 141 on Windows" from a User-Agent header; the raw string stays in the audit log.
 * @param {string} userAgent
 */
function describeDevice(userAgent) {
    const ua = String(userAgent || '');
    if (!ua) return 'Unknown';
    const browsers = [
        ['Edge', /Edg(?:e|A|iOS)?\/(\d+)/],
        ['Opera', /OPR\/(\d+)/],
        ['Firefox', /(?:Firefox|FxiOS)\/(\d+)/],
        ['Chrome', /(?:Chrome|CriOS)\/(\d+)/],
        ['Safari', /Version\/(\d+)[\d.]* .*Safari\//],
    ];
    let browser = null;
    for (const [name, pattern] of browsers) {
        const match = pattern.exec(ua);
        if (match) {
            browser = `${name} ${match[1]}`;
            break;
        }
    }
    let os = null;
    if (/Windows NT/.test(ua)) os = 'Windows';
    else if (/iPhone|iPad|iPod/.test(ua)) os = 'iOS';
    else if (/Android/.test(ua)) os = 'Android';
    else if (/Mac OS X|Macintosh/.test(ua)) os = 'macOS';
    else if (/CrOS/.test(ua)) os = 'ChromeOS';
    else if (/Linux/.test(ua)) os = 'Linux';
    if (browser && os) return `${browser} on ${os}`;
    if (browser || os) return browser || os;
    return ua.length > 80 ? `${ua.slice(0, 77)}...` : ua;
}

function noticesOf(m) {
    return m.notices || (m.notice ? [m.notice] : []);
}

// ---- Plain text ----

function wrapText(text, width = 76) {
    const words = String(text).split(/\s+/).filter(Boolean);
    const lines = [];
    let line = '';
    for (const word of words) {
        if (line && (line.length + 1 + word.length) > width) {
            lines.push(line);
            line = word;
        } else {
            line = line ? `${line} ${word}` : word;
        }
    }
    if (line) lines.push(line);
    return lines.join('\n');
}

function renderText(m) {
    const out = [];
    out.push(m.portalName, '='.repeat(Math.min(60, Math.max(m.portalName.length, 12))), '');
    out.push(m.heading, '');
    if (m.greeting) out.push(m.greeting, '');
    for (const paragraph of m.intro || []) out.push(wrapText(paragraph), '');
    if (m.details?.length) {
        const width = Math.max(...m.details.map(([label]) => label.length)) + 2;
        for (const [label, value] of m.details) out.push(`${`${label}:`.padEnd(width)}${value}`);
        out.push('');
    }
    for (const notice of noticesOf(m)) {
        if (notice.title) out.push(`>> ${notice.title}`);
        out.push(wrapText(notice.text), '');
    }
    if (m.steps?.length) {
        if (m.stepsTitle) out.push(m.stepsTitle);
        m.steps.forEach((step, i) => out.push(wrapText(`${i + 1}. ${step}`)));
        out.push('');
    }
    if (m.action?.url) out.push(`${m.action.label}: ${m.action.url}`, '');
    for (const paragraph of m.outro || []) out.push(wrapText(paragraph), '');
    out.push('--');
    for (const line of m.footer) out.push(wrapText(line));
    return out.join('\n');
}

// ---- HTML ----

function paragraphHtml(text, { color = COLORS.text, size = 15, margin = '0 0 16px' } = {}) {
    return `<p style="margin:${margin};font-family:${FONT};font-size:${size}px;line-height:1.55;color:${color};">${esc(text)}</p>`;
}

function detailsHtml(details) {
    const rows = details.map(([label, value], i) => {
        const top = i === 0 ? '' : `border-top:1px solid ${COLORS.border};`;
        return `<tr>`
            + `<td style="${top}padding:10px 14px;width:34%;background:${COLORS.labelBg};font-family:${FONT};font-size:13px;color:${COLORS.secondary};vertical-align:top;">${esc(label)}</td>`
            + `<td style="${top}padding:10px 14px;font-family:${FONT};font-size:14px;color:${COLORS.text};vertical-align:top;word-break:break-word;">${esc(value)}</td>`
            + `</tr>`;
    }).join('');
    return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" `
        + `style="border:1px solid ${COLORS.border};border-radius:4px;border-collapse:separate;margin:0 0 20px;">${rows}</table>`;
}

function noticeHtml({ tone = 'info', title, text }) {
    const c = COLORS.notice[tone] || COLORS.notice.info;
    return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px;">`
        + `<tr><td style="background:${c.bg};border:1px solid ${c.border};border-left:4px solid ${c.border};border-radius:4px;padding:12px 16px;">`
        + (title ? `<p style="margin:0 0 4px;font-family:${FONT};font-size:14px;font-weight:600;color:${c.text};">${esc(title)}</p>` : '')
        + `<p style="margin:0;font-family:${FONT};font-size:14px;line-height:1.5;color:${c.text};">${esc(text)}</p>`
        + `</td></tr></table>`;
}

function stepsHtml(title, steps) {
    const items = steps.map((step) => `<li style="margin:0 0 6px;">${esc(step)}</li>`).join('');
    return (title ? `<p style="margin:0 0 8px;font-family:${FONT};font-size:15px;font-weight:600;color:${COLORS.text};">${esc(title)}</p>` : '')
        + `<ol style="margin:0 0 20px;padding-left:22px;font-family:${FONT};font-size:15px;line-height:1.55;color:${COLORS.text};">${items}</ol>`;
}

function actionHtml({ label, url }) {
    // A button that works without images or CSS support, plus the address written out underneath
    return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 8px;"><tr>`
        + `<td style="background:${COLORS.primary};border-radius:4px;">`
        + `<a href="${esc(url)}" style="display:inline-block;padding:11px 22px;font-family:${FONT};font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;">${esc(label)}</a>`
        + `</td></tr></table>`
        + `<p style="margin:0 0 20px;font-family:${FONT};font-size:13px;color:${COLORS.muted};">Or open <a href="${esc(url)}" style="color:${COLORS.primary};">${esc(url)}</a> in your browser.</p>`;
}

function renderHtml(m) {
    const body = [
        `<h1 style="margin:0 0 16px;font-family:${FONT};font-size:21px;line-height:1.3;font-weight:600;color:${COLORS.text};">${esc(m.heading)}</h1>`,
        m.greeting ? paragraphHtml(m.greeting) : '',
        ...(m.intro || []).map((p) => paragraphHtml(p)),
        m.details?.length ? detailsHtml(m.details) : '',
        ...noticesOf(m).map(noticeHtml),
        m.steps?.length ? stepsHtml(m.stepsTitle, m.steps) : '',
        m.action?.url ? actionHtml(m.action) : '',
        ...(m.outro || []).map((p) => paragraphHtml(p, { color: COLORS.secondary, size: 14 })),
    ].join('\n');
    const footer = m.footer.map((line) => paragraphHtml(line, { color: COLORS.muted, size: 12, margin: '0 0 6px' })).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<title>${esc(m.subject)}</title>
</head>
<body style="margin:0;padding:0;background:${COLORS.page};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${COLORS.page};">${esc(m.preheader || m.heading)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${COLORS.page};">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background:${COLORS.surface};border:1px solid ${COLORS.border};border-radius:6px;">
<tr><td style="background:${COLORS.header};border-bottom:3px solid ${COLORS.accent};border-radius:6px 6px 0 0;padding:16px 28px;font-family:${FONT};font-size:16px;font-weight:600;color:#ffffff;">${esc(m.portalName)}</td></tr>
<tr><td style="padding:28px 28px 8px;">
${body}
</td></tr>
<tr><td style="padding:16px 28px 22px;border-top:1px solid ${COLORS.border};">
${footer}
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

/**
 * @param {object} m
 * @param {string} m.portalName   - shown in the header bar and the footer
 * @param {string} m.subject
 * @param {string} m.heading      - first line of the body
 * @param {string} [m.preheader]  - inbox preview text (hidden in the body)
 * @param {string} [m.greeting]   - "Hello Name,"
 * @param {string[]} [m.intro]    - paragraphs
 * @param {Array<[string, string]>} [m.details] - label/value rows
 * @param {{tone?: 'neutral'|'info'|'warning'|'danger'|'success', title?: string, text: string}} [m.notice]
 * @param {Array<{tone?: string, title?: string, text: string}>} [m.notices] - instead of notice, several boxes
 * @param {string} [m.stepsTitle]
 * @param {string[]} [m.steps]    - numbered steps
 * @param {{label: string, url: string}} [m.action] - the only link; omitted when url is empty
 * @param {string[]} [m.outro]    - closing paragraphs
 * @param {string[]} m.footer     - small print
 * @returns {{subject: string, text: string, html: string}}
 */
function render(m) {
    return { subject: m.subject, text: renderText(m), html: renderHtml(m) };
}

module.exports = { render, describeDevice, esc };
