// Mail layout: both parts carry the same content, every value is escaped, and the HTML stays spam-filter friendly.
require('../helpers/setup');
const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { render, describeDevice } = require('../../server/services/mailTemplate');

const BASE = {
    portalName: 'Test Portal',
    subject: 'Your password was changed',
    heading: 'Your password was changed',
    greeting: 'Hello Sample User,',
    intro: ['The password for your account sample was changed.'],
    details: [['Account', 'sample'], ['IP address', '192.0.2.10']],
    notices: [{ tone: 'info', title: 'Was this you?', text: 'If you did not make this change, contact IT immediately.' }],
    steps: ['Open the portal.', 'Sign in.'],
    stepsTitle: 'How to change it',
    action: { label: 'Open the password portal', url: 'https://portal.example.test' },
    footer: ['This message was sent automatically.'],
};

describe('mailTemplate', () => {
    test('the text and HTML parts carry the same content', () => {
        const { subject, text, html } = render(BASE);
        assert.equal(subject, 'Your password was changed');
        for (const piece of ['Test Portal', 'Hello Sample User,', 'Account', '192.0.2.10', 'Was this you?',
            'How to change it', 'Sign in.', 'This message was sent automatically.']) {
            assert.ok(text.includes(piece), `text has ${piece}`);
            assert.ok(html.includes(piece), `html has ${piece}`);
        }
        assert.match(text, /Open the password portal: https:\/\/portal\.example\.test/);
        assert.match(text, /^1\. Open the portal\.$/m);
    });

    test('details line up in the text part', () => {
        const { text } = render(BASE);
        assert.match(text, /^Account:    sample$/m);
        assert.match(text, /^IP address: 192\.0\.2\.10$/m);
    });

    test('every value is HTML-escaped', () => {
        const { html } = render({ ...BASE, details: [['Account', '<script>alert(1)</script>'], ['Name', 'O\'Brien & "Co"']] });
        assert.doesNotMatch(html, /<script>alert/);
        assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
        assert.match(html, /O&#39;Brien &amp; &quot;Co&quot;/);
    });

    test('the HTML links only to the action URL and loads nothing external', () => {
        const { html } = render(BASE);
        const links = [...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
        assert.deepEqual([...new Set(links)], ['https://portal.example.test']);
        assert.doesNotMatch(html, /<img|<script|<link|<style|@import|url\(/i);
        // Visible link text is the address itself, never "click here"
        assert.match(html, />https:\/\/portal\.example\.test<\/a>/);
        assert.doesNotMatch(html, /click here/i);
    });

    test('without a URL there is no button and no link', () => {
        const { text, html } = render({ ...BASE, action: null });
        assert.doesNotMatch(html, /href=/);
        assert.doesNotMatch(text, /https?:\/\//);
    });

    test('the category shows in the header of both parts', () => {
        const { text, html } = render({ ...BASE, category: 'Security alert' });
        assert.match(text, /^Test Portal - Security alert$/m);
        assert.match(html, />Security alert</);
    });

    test('layout survives Outlook: spacing from cell padding, button padding on its cell', () => {
        const { html } = render(BASE);
        // Outlook's Word engine ignores margins on tables and padding on links
        assert.doesNotMatch(html, /<table[^>]*style="[^"]*margin/i, 'no table margins');
        assert.match(html, /mso-padding-alt:12px 26px/);
        assert.match(html, /mso-line-height-rule:exactly/);
    });

    test('a single notice works as well as a list', () => {
        const { text } = render({ ...BASE, notices: undefined, notice: { text: 'Only one notice.' } });
        assert.match(text, /Only one notice\./);
    });

    test('devices are named from the User-Agent', () => {
        assert.equal(describeDevice('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'), 'Chrome 141 on Windows');
        assert.equal(describeDevice('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0'), 'Edge 141 on Windows');
        assert.equal(describeDevice('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'), 'Safari 18 on iOS');
        assert.equal(describeDevice('Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'), 'Firefox 140 on Linux');
        assert.equal(describeDevice(''), 'Unknown');
    });
});
