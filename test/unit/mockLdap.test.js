require('../helpers/setup');
const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const ldapService = require('../../server/services/ldapService');
const mockAd = require('../../server/services/mockLdapService');

beforeEach(() => mockAd.reset());

test('ldapService resolves to the mock when AD_MOCK=true', () => {
    assert.equal(ldapService, mockAd);
});

test('authenticates seeded users case-insensitively', async () => {
    const user = await ldapService.authenticateUser('JSmith', 'Passw0rd!');
    assert.equal(user.sAMAccountName, 'jsmith');
    assert.ok(user.dn.startsWith('CN=John Smith,'));
});

test('rejects bad credentials, unknown, disabled, and locked-out accounts', async () => {
    await assert.rejects(ldapService.authenticateUser('jsmith', 'wrong'), /Invalid credentials/);
    await assert.rejects(ldapService.authenticateUser('nobody', 'x'), /User not found/);
    await assert.rejects(ldapService.authenticateUser('disabled.user', 'Passw0rd!'), /Account is disabled/);
    await assert.rejects(ldapService.authenticateUser('locked.user', 'Passw0rd!'), /Account is locked out/);
});

test('identifies admin group membership', async () => {
    assert.equal(ldapService.isAdmin(await ldapService.findUser('admin')), true);
    assert.equal(ldapService.isAdmin(await ldapService.findUser('jsmith')), false);
});

test('enforces password policy: complexity, username, history', async () => {
    const { dn } = await ldapService.findUser('jsmith');
    await assert.rejects(ldapService.changePassword(dn, 'short1A'), /password policy/);
    await assert.rejects(ldapService.changePassword(dn, 'alllowercase1'), /password policy/);
    await assert.rejects(ldapService.changePassword(dn, 'Xjsmith#2026'), /password policy/);
    await assert.rejects(ldapService.changePassword(dn, 'Passw0rd!'), /password policy/);

    await ldapService.changePassword(dn, 'N3w-Secure-Pass');
    await ldapService.authenticateUser('jsmith', 'N3w-Secure-Pass');
    await assert.rejects(ldapService.authenticateUser('jsmith', 'Passw0rd!'), /Invalid credentials/);
});

test('changePasswordWithOld verifies the current password', async () => {
    const { dn } = await ldapService.findUser('jsmith');
    await assert.rejects(ldapService.changePasswordWithOld(dn, 'wrong', 'N3w-Secure-Pass'), /Invalid credentials/);
    await ldapService.changePasswordWithOld(dn, 'Passw0rd!', 'N3w-Secure-Pass');
    await ldapService.authenticateUser('jsmith', 'N3w-Secure-Pass');
});

test('findUser returns copies that cannot mutate the directory', async () => {
    const user = await ldapService.findUser('admin');
    user.memberOf.length = 0;
    assert.equal(ldapService.isAdmin(await ldapService.findUser('admin')), true);
});
