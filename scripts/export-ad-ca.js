// Exports the enterprise root CA certificate(s) published in AD to PEM files for AD_CA_CERT_PATH.
// Usage: node scripts/export-ad-ca.js [outputDir]
// The first connection is unverified (that is what this bootstraps) — compare the printed
// SHA-256 fingerprint with your CA (certutil -ca.cert / the CA console) before trusting it.
require('../server/config/secrets').loadSecrets();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ldap = require('ldapjs');

const url = process.env.AD_URL;
const baseDN = process.env.AD_BASE_DN;
const outDir = process.argv[2] || path.join(__dirname, '..', 'certs');
const tlsOptions = { rejectUnauthorized: false, servername: process.env.AD_TLS_SERVERNAME || undefined };

function toPem(der) {
    const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

async function main() {
    if (!url || !baseDN || !process.env.AD_BIND_DN) throw new Error('Set AD_URL, AD_BASE_DN, AD_BIND_DN and AD_BIND_PASSWORD in .env');

    const client = ldap.createClient({ url, connectTimeout: 10000, timeout: 15000, tlsOptions });
    client.on('error', (err) => { throw err; });

    if (url.startsWith('ldap://')) {
        await new Promise((resolve, reject) => client.once('connect', () =>
            client.starttls(tlsOptions, [], (err) => (err ? reject(err) : resolve()))));
    }
    await new Promise((resolve, reject) =>
        client.bind(process.env.AD_BIND_DN, process.env.AD_BIND_PASSWORD, (err) => (err ? reject(err) : resolve())));

    const searchBase = `CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,${baseDN}`;
    const certs = await new Promise((resolve, reject) => {
        const found = [];
        client.search(searchBase, { scope: 'one', filter: '(objectClass=certificationAuthority)', attributes: ['cn', 'cACertificate'] }, (err, res) => {
            if (err) return reject(err);
            res.on('searchEntry', (entry) => {
                const cn = entry.attributes.find((a) => a.type === 'cn')?.values[0];
                const attr = entry.attributes.find((a) => a.type.toLowerCase() === 'cacertificate');
                (attr?.buffers || []).forEach((der) => found.push({ cn, der }));
            });
            res.on('error', reject);
            res.on('end', () => resolve(found));
        });
    });
    client.unbind(() => {});

    if (certs.length === 0) throw new Error(`No CA certificates found under ${searchBase}`);

    fs.mkdirSync(outDir, { recursive: true });
    for (const { cn, der } of certs) {
        const x509 = new crypto.X509Certificate(der);
        const file = path.join(outDir, `${String(cn).replace(/[^\w.-]/g, '_')}.pem`);
        fs.writeFileSync(file, toPem(der));
        console.log(`Saved ${file}`);
        console.log(`  Subject: ${x509.subject.replace(/\n/g, ', ')}`);
        console.log(`  Valid:   ${x509.validFrom} -> ${x509.validTo}`);
        console.log(`  SHA-256: ${x509.fingerprint256}`);
    }
    console.log('\nVerify the fingerprint with your CA administrator, then set AD_CA_CERT_PATH to the file.');
}

main().catch((err) => {
    console.error(`[export-ad-ca] Failed: ${err.message}`);
    process.exit(1);
});
