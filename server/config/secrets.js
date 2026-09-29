// Loads .env and decrypts values protected with Windows DPAPI (see scripts/protect-secret.ps1).
//   dpapi:<data>          CurrentUser scope — only the Windows account that encrypted it can decrypt
//   dpapi-machine:<data>  LocalMachine scope — any process on this server can decrypt
const { spawnSync } = require('child_process');

const SECRET_KEYS = ['AD_BIND_PASSWORD', 'PG_PASSWORD', 'JWT_SECRET', 'TOTP_ENCRYPTION_KEY', 'TLS_PFX_PASSPHRASE'];

const DECRYPT_SCRIPT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$in = [Console]::In.ReadToEnd().Trim()
if ($in.StartsWith('dpapi-machine:')) {
    $bytes = [Convert]::FromBase64String($in.Substring(14))
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, 'LocalMachine')
    [Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain))
} else {
    $secure = ConvertTo-SecureString $in.Substring(6)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}`;

function isProtected(value) {
    return typeof value === 'string' && (value.startsWith('dpapi:') || value.startsWith('dpapi-machine:'));
}

function decrypt(name, value) {
    if (process.platform !== 'win32') {
        throw new Error(`${name} is DPAPI-protected, which is only supported on Windows.`);
    }
    // Ciphertext goes via stdin so it never appears in process listings
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', DECRYPT_SCRIPT], {
        input: value,
        encoding: 'utf8',
        windowsHide: true,
    });
    if (result.status !== 0 || !result.stdout) {
        throw new Error(
            `Cannot decrypt ${name}. DPAPI values can only be decrypted by the same Windows account `
            + '(dpapi:) or on the same server (dpapi-machine:) that encrypted them.'
        );
    }
    return result.stdout;
}

let loaded = false;

function loadSecrets() {
    if (loaded) return;
    require('dotenv').config({ quiet: true });
    for (const key of SECRET_KEYS) {
        if (isProtected(process.env[key])) process.env[key] = decrypt(key, process.env[key]);
    }
    loaded = true;
}

module.exports = { loadSecrets, SECRET_KEYS };
