require('../helpers/setup');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createWindowsDirectory, accountName } = require('../../server/services/windowsDirectoryService');

const escapeFilterValue = (v) => String(v).replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
const windowsOnly = { skip: process.platform !== 'win32' && 'AD2_MODE=windows needs Windows PowerShell' };

test('accountName strips the domain from DOMAIN\\user and user@domain', () => {
    assert.equal(accountName(String.raw`MAIL\svc-pwreset`), 'svc-pwreset');
    assert.equal(accountName('svc-pwreset@mail.example.test'), 'svc-pwreset');
    assert.equal(accountName('svc-pwreset'), 'svc-pwreset');
});

test('reports an unreachable DC for lookups and password writes', windowsOnly, async () => {
    // Nothing listens on 127.0.0.1:389 here; the helper must start, decode its input and report the failure
    const dir = createWindowsDirectory({
        name: 'Mail',
        server: '127.0.0.1',
        bindDN: String.raw`TEST\svc`,
        bindPassword: 'pässwörd"€',
        rawSearchBase: 'DC=test,DC=local',
    }, escapeFilterValue);

    await assert.rejects(dir.findUser('jsmith*)(x'), /Directory server unreachable: 127\.0\.0\.1/);
    await assert.rejects(dir.changePassword('CN=x,DC=test,DC=local', 'Nëw-Pass"1'), /Directory server unreachable: 127\.0\.0\.1/);
    await assert.rejects(dir.listPasswordExpiries(), /Directory server unreachable: 127\.0\.0\.1/);
});
