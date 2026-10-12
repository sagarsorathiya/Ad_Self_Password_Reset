// Second-domain directory for AD2_MODE=windows: same interface as ldapService's createDirectory(),
// implemented by windowsDirectory.ps1 (ADSI with Kerberos/NTLM sign-and-seal, no certificate).
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { fileTimeToDate } = require('./adTime');

const SCRIPT = fs.readFileSync(path.join(__dirname, 'windowsDirectory.ps1'), 'utf8');
// -EncodedCommand is not subject to the execution policy and needs no quoting
const ENCODED_SCRIPT = Buffer.from(SCRIPT, 'utf16le').toString('base64');
const TIMEOUT_MS = 30000;

// sAMAccountName part of DOMAIN\user or user@domain
function accountName(bindUser) {
    return String(bindUser).replace(/^.*\\/, '').replace(/@.*$/, '');
}

/**
 * @param {object} ad - config.ad.secondary (mode 'windows')
 * @param {function} escapeFilterValue - RFC 4515 escaping from ldapService
 */
function createWindowsDirectory(ad, escapeFilterValue) {
    function run(request) {
        return new Promise((resolve, reject) => {
            const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', ENCODED_SCRIPT], {
                windowsHide: true,
            });
            let stdout = '';
            const timer = setTimeout(() => {
                child.kill();
                reject(new Error(`Directory server unreachable: no answer from ${ad.server} within ${TIMEOUT_MS / 1000}s`));
            }, TIMEOUT_MS);

            child.stdout.on('data', (chunk) => { stdout += chunk; });
            child.on('error', (err) => {
                clearTimeout(timer);
                reject(new Error(`Cannot start PowerShell: ${err.message}`));
            });
            child.on('close', () => {
                clearTimeout(timer);
                let result;
                try {
                    result = JSON.parse(Buffer.from(stdout.trim(), 'base64').toString('utf8'));
                } catch {
                    reject(new Error('Directory helper returned no result'));
                    return;
                }
                if (result.ok) resolve(result);
                else reject(new Error(describeError(result.error)));
            });

            // Credentials and the new password travel only through stdin
            const payload = {
                server: ad.server,
                bindUser: ad.bindDN,
                bindPassword: ad.bindPassword,
                searchBase: ad.rawSearchBase,
                ...request,
            };
            child.stdin.end(Buffer.from(JSON.stringify(payload), 'utf8').toString('base64'));
        });
    }

    // Same wording as ldapService so the controllers' error handling applies unchanged
    function describeError(error = '') {
        if (/0000052D/i.test(error)) return 'Password does not meet the domain password policy requirements';
        if (/0x8007202B/i.test(error)) {
            return `Failed to change password: ${ad.server} is a read-only domain controller; set AD2_SERVER to a writable DC (${error})`;
        }
        if (/0x8007052E|user name or password is incorrect/i.test(error)) {
            return `LDAP bind failed: AD2_BIND_DN/AD2_BIND_PASSWORD rejected by ${ad.server} (${error})`;
        }
        if (/0x8007203A|server is not operational/i.test(error)) {
            return `Directory server unreachable: ${ad.server} (${error})`;
        }
        return `Directory error: ${error}`;
    }

    async function findUser(username) {
        const { user } = await run({ op: 'findUser', filterValue: escapeFilterValue(username) });
        return user;
    }

    async function changePassword(userDN, newPassword) {
        await run({ op: 'changePassword', dn: userDN, newPassword });
    }

    // Same shape as ldapService.listPasswordExpiries()
    async function listPasswordExpiries() {
        const { users } = await run({ op: 'listPasswordExpiries' });
        // Windows PowerShell may turn a one-element array into a single object
        const list = Array.isArray(users) ? users : users ? [users] : [];
        return list.map((u) => ({
            dn: u.dn,
            username: u.sAMAccountName,
            displayName: u.displayName || '',
            mail: u.mail,
            adminCount: u.adminCount,
            expiresAt: fileTimeToDate(u.passwordExpiryTime),
        }));
    }

    async function isServiceAccountPrivileged() {
        const { privileged } = await run({ op: 'isPrivileged', filterValue: escapeFilterValue(accountName(ad.bindDN)) });
        return privileged;
    }

    return {
        name: ad.name,
        findUser,
        changePassword,
        listPasswordExpiries,
        isServiceAccountPrivileged,
    };
}

module.exports = { createWindowsDirectory, accountName };
