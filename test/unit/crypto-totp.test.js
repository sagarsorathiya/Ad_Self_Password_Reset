require('../helpers/setup');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cryptoService = require('../../server/services/cryptoService');
const totpService = require('../../server/services/totpService');
const { totpCode } = require('../helpers/setup');

test('AES-256-GCM round-trips and produces unique ciphertexts', () => {
    const a = cryptoService.encrypt('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
    const b = cryptoService.encrypt('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
    assert.notEqual(a, b);
    assert.equal(cryptoService.decrypt(a), 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
});

test('decrypt rejects tampered ciphertext', () => {
    const [iv, tag, data] = cryptoService.encrypt('secret').split(':');
    const flipped = (parseInt(data[0], 16) ^ 1).toString(16) + data.slice(1);
    assert.throws(() => cryptoService.decrypt(`${iv}:${tag}:${flipped}`));
    assert.throws(() => cryptoService.decrypt('not-valid'));
});

test('TOTP secrets survive encrypt/decrypt and verify', () => {
    const secret = totpService.generateSecret();
    const stored = totpService.encryptSecret(secret);
    assert.equal(totpService.decryptSecret(stored), secret);
    assert.equal(totpService.verifyToken(totpCode(secret), secret), true);
});

test('TOTP accepts ±1 step and rejects older codes', () => {
    const secret = totpService.generateSecret();
    assert.equal(totpService.verifyToken(totpCode(secret, -30), secret), true);
    assert.equal(totpService.verifyToken(totpCode(secret, 30), secret), true);
    assert.equal(totpService.verifyToken(totpCode(secret, -90), secret), false);
});

test('TOTP rejects malformed input', () => {
    const secret = totpService.generateSecret();
    for (const bad of ['', 'abcdef', '12345', '1234567', null, undefined, ['1', '2', '3', '4', '5', '6']]) {
        assert.equal(totpService.verifyToken(bad, secret), false, `accepted ${JSON.stringify(bad)}`);
    }
});

test('otpauth URI contains issuer and account', () => {
    const uri = totpService.generateKeyUri(totpService.generateSecret(), 'jsmith');
    assert.match(uri, /^otpauth:\/\/totp\//);
    assert.match(uri, /jsmith/);
    assert.match(uri, /issuer=/);
});
