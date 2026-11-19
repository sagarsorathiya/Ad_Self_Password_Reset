// Layout for every mail the portal sends: one structured description -> a plain-text part and an HTML part
// with the same content (multipart/alternative, which mail filters expect from a legitimate sender).
// Pure (no I/O), so it is unit-tested.
//
// Deliberate choices, each one because filters or users treat the opposite as a sign of spam or phishing:
//   - no images, web fonts, scripts or external resources; every style is inline (mail clients drop <style>)
//   - the portal address is the only link, and its visible text is the address itself, never "click here"
//   - no capitals for emphasis, no exclamation marks, no urgency words in subjects
//   - the HTML and the text part say the same thing; every dynamic value is HTML-escaped
//
// Built for Outlook's Word renderer as well as browsers and web mail (seen in production 2026-11-19: Outlook
// ignored table margins and link padding, so the button was cramped and touched the box above it):
//   - spacing comes only from cell padding: every block sits in its own row of one table, never from margins
//   - the button's padding is on its cell (with mso-padding-alt), so it survives where <a> padding is ignored
//   - fixed pixel line heights (mso-line-height-rule:exactly) and bgcolor attributes next to background styles

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
    footerBg: '#f8f9fb',
    notice: {
        neutral: { bg: '#f8f9fb', border: '#c3cad3', text: '#1d2733' },
        info: { bg: '#fff8eb', border: '#f5d9a8', text: '#7c2d12' },
        warning: { bg: '#fdf4e3', border: '#e9b44c', text: '#6b3f00' },
        danger: { bg: '#fdeceb', border: '#e58b84', text: '#8a1c13' },
        success: { bg: '#e8f5ec', border: '#8fcca3', text: '#14532d' },
    },
};
const FONT = "'Segoe UI', Arial, Helvetica, sans-serif";
const SIDE = 32; // horizontal padding of the content column, px

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
    const title = m.category ? `${m.portalName} - ${m.category}` : m.portalName;
    out.push(title, '='.repeat(Math.min(72, Math.max(title.length, 12))), '');
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

// Text style with a fixed line height, so Outlook does not stretch or squash lines
function textStyle({ size = 15, lineHeight = 24, color = COLORS.text, weight = 400 } = {}) {
    return `font-family:${FONT};font-size:${size}px;line-height:${lineHeight}px;mso-line-height-rule:exactly;color:${color};font-weight:${weight};`;
}

// One content block in its own row; the bottom padding is the space to the next block
function block(inner, bottom = 20) {
    return `<tr><td style="padding:0 ${SIDE}px ${bottom}px ${SIDE}px;">${inner}</td></tr>`;
}

function paragraphHtml(text, options) {
    return `<div style="${textStyle(options)}">${esc(text)}</div>`;
}

function detailsHtml(details) {
    const rows = details.map(([label, value], i) => {
        const top = i === 0 ? '' : `border-top:1px solid ${COLORS.border};`;
        return `<tr>`
            + `<td width="170" bgcolor="${COLORS.labelBg}" valign="top" style="${top}width:170px;padding:9px 14px;background:${COLORS.labelBg};${textStyle({ size: 13, lineHeight: 20, color: COLORS.secondary })}">${esc(label)}</td>`
            + `<td valign="top" style="${top}padding:9px 14px;${textStyle({ size: 14, lineHeight: 20 })}word-break:break-word;">${esc(value)}</td>`
            + `</tr>`;
    }).join('');
    return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" `
        + `style="width:100%;border:1px solid ${COLORS.border};border-collapse:collapse;">${rows}</table>`;
}

function noticeHtml({ tone = 'info', title, text }) {
    const c = COLORS.notice[tone] || COLORS.notice.info;
    return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;border-collapse:collapse;"><tr>`
        + `<td bgcolor="${c.bg}" style="background:${c.bg};border:1px solid ${c.border};border-left:4px solid ${c.border};padding:12px 16px;">`
        + (title ? `<div style="${textStyle({ size: 14, lineHeight: 20, color: c.text, weight: 600 })}padding:0 0 4px;">${esc(title)}</div>` : '')
        + `<div style="${textStyle({ size: 14, lineHeight: 21, color: c.text })}">${esc(text)}</div>`
        + `</td></tr></table>`;
}

function stepsHtml(title, steps) {
    // Numbers as table cells rather than <ol>: list indents differ wildly between clients
    const rows = steps.map((step, i) => `<tr>`
        + `<td width="26" valign="top" style="width:26px;padding:0 0 8px;${textStyle({ size: 15, lineHeight: 23, color: COLORS.primary, weight: 600 })}">${i + 1}.</td>`
        + `<td valign="top" style="padding:0 0 8px;${textStyle({ size: 15, lineHeight: 23 })}">${esc(step)}</td>`
        + `</tr>`).join('');
    return (title ? `<div style="${textStyle({ size: 15, lineHeight: 22, weight: 600 })}padding:0 0 10px;">${esc(title)}</div>` : '')
        + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;">${rows}</table>`;
}

function actionHtml({ label, url }) {
    // Padding on the cell (mso-padding-alt for Outlook) plus inline-block padding on the link for everyone else
    return `<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>`
        + `<td bgcolor="${COLORS.primary}" style="background:${COLORS.primary};border-radius:4px;mso-padding-alt:12px 26px;">`
        + `<a href="${esc(url)}" style="display:inline-block;padding:12px 26px;${textStyle({ size: 15, lineHeight: 20, color: '#ffffff', weight: 600 })}text-decoration:none;border-radius:4px;">${esc(label)}</a>`
        + `</td></tr></table>`
        + `<div style="${textStyle({ size: 13, lineHeight: 20, color: COLORS.muted })}padding:10px 0 0;">Or open `
        + `<a href="${esc(url)}" style="color:${COLORS.primary};text-decoration:underline;">${esc(url)}</a> in your browser.</div>`;
}

function headerHtml(m) {
    const category = m.category
        ? `<td align="right" valign="middle" style="${textStyle({ size: 12, lineHeight: 18, color: COLORS.accent, weight: 600 })}white-space:nowrap;">${esc(m.category)}</td>`
        : '';
    return `<tr><td bgcolor="${COLORS.header}" style="background:${COLORS.header};border-bottom:3px solid ${COLORS.accent};padding:18px ${SIDE}px;">`
        + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;"><tr>`
        + `<td valign="middle" style="${textStyle({ size: 16, lineHeight: 22, color: '#ffffff', weight: 600 })}">${esc(m.portalName)}</td>`
        + category
        + `</tr></table></td></tr>`;
}

function renderHtml(m) {
    const rows = [
        // Space above the heading
        `<tr><td style="padding:30px ${SIDE}px 0 ${SIDE}px;font-size:0;line-height:0;">&nbsp;</td></tr>`,
        block(`<h1 style="margin:0;${textStyle({ size: 22, lineHeight: 30, weight: 600 })}">${esc(m.heading)}</h1>`, 18),
    ];
    if (m.greeting) rows.push(block(paragraphHtml(m.greeting), 14));
    for (const p of m.intro || []) rows.push(block(paragraphHtml(p), 22));
    if (m.details?.length) rows.push(block(detailsHtml(m.details), 22));
    for (const notice of noticesOf(m)) rows.push(block(noticeHtml(notice), 16));
    if (m.steps?.length) rows.push(block(stepsHtml(m.stepsTitle, m.steps), 16));
    if (m.action?.url) rows.push(block(actionHtml(m.action), 26));
    for (const p of m.outro || []) rows.push(block(paragraphHtml(p, { size: 14, lineHeight: 22, color: COLORS.secondary }), 18));
    // A little extra space above the footer
    rows.push(`<tr><td style="padding:0 0 6px;font-size:0;line-height:0;">&nbsp;</td></tr>`);

    const footer = m.footer
        .map((line) => `<div style="${textStyle({ size: 12, lineHeight: 18, color: COLORS.muted })}padding:0 0 6px;">${esc(line)}</div>`)
        .join('');

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
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${COLORS.page}" style="width:100%;background:${COLORS.page};">
<tr><td align="center" style="padding:28px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" bgcolor="${COLORS.surface}" style="width:100%;max-width:600px;background:${COLORS.surface};border:1px solid ${COLORS.border};border-collapse:collapse;">
${headerHtml(m)}
${rows.join('\n')}
<tr><td bgcolor="${COLORS.footerBg}" style="background:${COLORS.footerBg};border-top:1px solid ${COLORS.border};padding:18px ${SIDE}px 14px;">
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
 * @param {string} [m.category]   - small label on the right of the header, e.g. "Security alert"
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
