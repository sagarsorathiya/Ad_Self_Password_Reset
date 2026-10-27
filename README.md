# AD Self-Service Password Reset Portal

An **intranet** web portal that lets Active Directory users change their password and reset a forgotten password on their own. Users prove who they are with **security questions** or an **authenticator app (TOTP)**. Help-desk staff get an admin panel for enrollment tracking, account locking and an audit trail.

- Backend: Node.js 20+ (tested on 24), Express 5, `ldapjs`, PostgreSQL
- Frontend: plain HTML/CSS/JS with no build step and no external CDN or font requests, so it works on isolated networks
- Tests: 99 automated tests (`node:test`)

---

## Contents
1. [Features](#1-features)
2. [Architecture](#2-architecture)
3. [Quick start (development)](#3-quick-start-development)
4. [Configuration reference](#4-configuration-reference)
5. [Active Directory setup](#5-active-directory-setup)
6. [PostgreSQL setup](#6-postgresql-setup)
7. [Intranet deployment (Windows Server)](#7-intranet-deployment-windows-server)
8. [User guide](#8-user-guide)
9. [Admin guide](#9-admin-guide)
10. [Security model](#10-security-model)
11. [API reference](#11-api-reference)
12. [Testing](#12-testing)
13. [Maintenance & operations](#13-maintenance--operations)
14. [Troubleshooting](#14-troubleshooting)
15. [Known limitations](#15-known-limitations)

---

## 1. Features

| Area | Details |
|---|---|
| Sign-in | AD credentials checked by an LDAP bind. JWT access token (15 min) plus refresh token (7 days). |
| Enrollment | 3 security questions (answers hashed with bcrypt) and an authenticator app (QR code or manual key). |
| Forgot password | Username → choose a method → verify → set a new password with a single-use token valid for 10 minutes. |
| Change password | For signed-in users who have completed enrollment. The current password is checked against AD. |
| Second domain (optional) | Every change and reset also sets the same password in a second domain (same username), e.g. a separate mail domain. See §5.1. |
| Mail (optional) | Security alert after every password change or reset (time, IP address, browser, method). Daily reminders before the password expires. See §5.2. |
| Admin panel | Enrollment stats, user search and filters, lock/unlock, enrollment reset, portal admins, audit log viewer, security question management, password exception list (blocked words). |
| Security | Rate limiting, account lockout, TOTP replay protection, refresh-token revocation, audit log, CSP/Helmet. |

## 2. Architecture

```
Browser ──HTTPS──► Express (Node.js) ──LDAPS 636──► Active Directory
                        │
                        ├──TCP 5432──► PostgreSQL (enrollment, answers, TOTP secrets, audit)
                        │
                        └──SMTP 25───► Mail relay (optional: alerts and expiry reminders)
```

- **Passwords are never stored.** Every password operation goes straight to AD.
- **Admin rights** come from membership in the AD group set in `AD_ADMIN_GROUP`, or are granted to individual users in the admin panel (stored in the portal database).
- **Mail is optional.** Without `SMTP_HOST` the portal sends nothing.
- Layout: `server/` (config, controllers, middleware, routes, services, db/schema.sql), `public/` (pages and scripts), `scripts/` (database setup, mail test, reminder dry run, Windows helpers), `test/`.

## 3. Quick start (development)

Prerequisites: Node.js 20+ and PostgreSQL 13+.

```powershell
npm install
Copy-Item .env.example .env      # then edit: PG_*, JWT_SECRET, TOTP_ENCRYPTION_KEY, AD_MOCK=true
npm run db:init                  # creates the database and applies the schema (safe to re-run)
npm run dev                      # http://localhost:3000 (auto-restarts on change)
```

To generate secrets:
```powershell
node -e "const c=require('crypto');console.log('JWT_SECRET='+c.randomBytes(48).toString('hex'));console.log('TOTP_ENCRYPTION_KEY='+c.randomBytes(32).toString('hex'))"
```

With `AD_MOCK=true` the portal uses a built-in test directory instead of a domain controller:

| Username | Password | Notes |
|---|---|---|
| `jsmith` | `Passw0rd!` | regular user |
| `mjones` | `Welcome1!` | regular user |
| `admin` | `Adm1nPass!` | member of the admin group |
| `disabled.user` | `Passw0rd!` | disabled account |
| `locked.user` | `Passw0rd!` | locked-out account |

The mock resets whenever the server restarts. It applies AD-style rules: complexity, no username inside the password, and the last 3 passwords can't be reused. **The server refuses to start with `AD_MOCK=true` when `NODE_ENV=production`.**

## 4. Configuration reference

All settings live in `.env`, which is git-ignored.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Listen port |
| `HOST` | all interfaces | Bind address. Use `127.0.0.1` behind IIS so the Node port isn't reachable from the network. |
| `NODE_ENV` | `development` | Set to `production` on servers. This enables the startup checks and hides error details from clients. |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | – | PEM certificate and key for native HTTPS |
| `TLS_PFX_PATH` / `TLS_PFX_PASSPHRASE` | – | Alternative: a PFX exported from your internal CA |
| `TRUST_PROXY` | `false` | Set when behind IIS/nginx (`1`, `loopback`, or the proxy IP) so the real client IP is used |
| `CORS_ORIGIN` | empty | Comma-separated allowed origins. Leave empty for same-origin only (recommended). |
| `AD_MOCK` | `false` | Use the in-memory directory (development and tests only) |
| `AD_URL` | – | e.g. `ldaps://dc01.corp.local:636`, or `ldap://dc01.corp.local:389` together with `AD_STARTTLS=true` |
| `AD_STARTTLS` | `false` | Upgrade `ldap://` connections to TLS before binding (needed for password changes on 389) |
| `AD_CA_CERT_PATH` | – | PEM of the internal root CA that issued the DC certificate (`node scripts/export-ad-ca.js`) |
| `AD_TLS_SERVERNAME` | – | DC hostname on its certificate, only when `AD_URL` uses an IP address |
| `AD_BASE_DN` | – | e.g. `DC=corp,DC=local` |
| `AD_BIND_DN` / `AD_BIND_PASSWORD` | – | Service account (see §5) |
| `AD_USER_SEARCH_BASE` | – | OU searched for users, e.g. `OU=Staff,DC=corp,DC=local` |
| `AD_ADMIN_GROUP` | – | Full DN of the portal admin group |
| `AD_TLS_REJECT_UNAUTHORIZED` | `true` | Only set `false` for testing. Trust your CA instead (see §14). |
| `AD_DOMAIN_LABEL` | `Active Directory` | Name of the first domain in user messages (useful with a second domain) |
| `AD2_MODE` | `ldap` | Second domain (see §5.1): `ldap` = LDAPS/StartTLS with certificate checking; `windows` = Windows ADSI with Kerberos/NTLM sign-and-seal on port 389, no certificate (Windows servers only) |
| `AD2_URL` | – | `ldap` mode: second domain URL. Empty (and no `AD2_SERVER`) = disabled. |
| `AD2_SERVER` | – | `windows` mode: a **writable** DC of the second domain (hostname preferred, so Kerberos is used) |
| `AD2_STARTTLS` / `AD2_CA_CERT_PATH` / `AD2_TLS_SERVERNAME` / `AD2_TLS_REJECT_UNAUTHORIZED` | – | Same meaning as the `AD_*` settings, for the second domain |
| `AD2_BIND_DN` / `AD2_BIND_PASSWORD` | – | Service account in the second domain (*Reset password* delegation only). In `windows` mode use `DOMAIN\user` or `user@domain` instead of a DN. |
| `AD2_USER_SEARCH_BASE` | – | OU searched for the matching user in the second domain (`windows` mode: empty = whole domain) |
| `AD2_DOMAIN_LABEL` | `Secondary domain` | Name of the second domain in user messages, e.g. `Mail` |
| `PG_HOST` / `PG_PORT` / `PG_DATABASE` / `PG_USER` / `PG_PASSWORD` | – | PostgreSQL connection |
| `PG_SSL` / `PG_SSL_CA_PATH` | `false` / – | Encrypt the database connection (use it when PostgreSQL is on another server) |
| `PG_TEST_DATABASE` | `<PG_DATABASE>_test` | Database used by the integration tests (the name must end in `_test`) |
| `JWT_SECRET` | – | **Required in production**, at least 32 characters |
| `JWT_EXPIRY` / `JWT_REFRESH_EXPIRY` | `15m` / `7d` | Token lifetimes |
| `TOTP_ENCRYPTION_KEY` | – | **Required in production**, 64 hex characters (AES-256 key) |
| `TOTP_ISSUER` | `AD Password Reset Portal` | Name shown in authenticator apps |
| `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX` | `900000` / `5` | Limit for login, reset and verify, per IP and username |
| `RATE_LIMIT_GENERAL_MAX` | `100` | Limit for all API calls per IP in each window. On an intranet behind NAT or a shared proxy, raise it (e.g. `1000`). |
| `RESET_POLICY` | `both` | `both`: security questions **and** authenticator code (recommended). `totp_only`: authenticator only. `either`: one of the two. |
| `HTTP_REDIRECT_PORT` | – | Optional plain-HTTP port that only redirects to HTTPS (e.g. `80` with `PORT=443`) |
| `AD_ALLOW_PRIVILEGED_BIND` | `false` | Production refuses to start if `AD_BIND_DN` or `AD2_BIND_DN` is privileged (adminCount=1). Override only; it applies to both accounts unless `AD2_ALLOW_PRIVILEGED_BIND` is set. |
| `SMTP_HOST` / `SMTP_PORT` | – / `25` | SMTP relay for alerts and reminders. Empty = no mail is sent. |
| `SMTP_SECURE` | `false` | `true` for implicit TLS (port 465). Otherwise STARTTLS is used whenever the server offers it. |
| `SMTP_USER` / `SMTP_PASSWORD` | – | Only if the relay requires a login. `SMTP_PASSWORD` can be DPAPI-encrypted. |
| `SMTP_CA_CERT_PATH` / `SMTP_TLS_REJECT_UNAUTHORIZED` | – / `true` | CA for the mail server certificate. Set `false` only for a relay with a self-signed certificate. |
| `MAIL_FROM` | – | Sender, e.g. `IT Service Desk <it-noreply@corp.example>`. Required with `SMTP_HOST`. |
| `PORTAL_NAME` / `PORTAL_URL` | `TOTP_ISSUER` / – | Name used in mails; portal address shown in alerts and reminders. |
| `PASSWORD_REMINDERS` | `false` | `true` = daily expiry reminders (needs `SMTP_HOST`). |
| `PASSWORD_REMINDER_DAYS` / `PASSWORD_REMINDER_HOUR` | `14,7,6,5,4,3,2,1` / `9` | Days before expiry that get a reminder; local hour of the daily run. |
| `PASSWORD_REMINDER_SOURCE` | `primary` | Domain whose password expiry is used. `secondary` when only the second domain expires passwords. |
| `AD2_ALLOW_PRIVILEGED_BIND` | – | Override for `AD2_BIND_DN` only. Set `true` (with `AD_ALLOW_PRIVILEGED_BIND=false`) to keep the first-domain check active while the second domain uses a privileged account. |

### Encrypting secrets in `.env`
Run `.\scripts\protect-secret.ps1` to encrypt every plain-text secret in `.env` (`AD_BIND_PASSWORD`, `AD2_BIND_PASSWORD`, `PG_PASSWORD`, `JWT_SECRET`, `TOTP_ENCRYPTION_KEY`, `TLS_PFX_PASSPHRASE`, `SMTP_PASSWORD`) with **Windows DPAPI**. Values become `dpapi:…` and are decrypted in memory at startup.
- Default scope is **CurrentUser**: run the script as the **same Windows account that runs the portal/service**. For a service running as LocalSystem, use `-Machine` (any process on that server can decrypt, but a copied `.env` is useless elsewhere).
- To change one value: `.\scripts\protect-secret.ps1 -Name AD_BIND_PASSWORD` (hidden prompt).
- Encrypted values can't be moved to another server or account. **Keep `TOTP_ENCRYPTION_KEY` in your password vault**; if it's lost, every user has to enroll again.
- If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope Process Bypass` in that window first.

> **Important:** never change `TOTP_ENCRYPTION_KEY` after users have enrolled. Their stored authenticator secrets can no longer be decrypted, and every user would have to enroll again. Back it up with your other secrets.

## 5. Active Directory setup

1. **An encrypted LDAP connection is required.** AD only accepts password writes (`unicodePwd`) over an encrypted connection, and each DC needs a certificate, usually from AD CS. Use one of these:
   - **LDAPS:** `AD_URL=ldaps://dc01.corp.local:636`
   - **StartTLS on 389**, when only 389 is open: `AD_URL=ldap://dc01.corp.local:389` and `AD_STARTTLS=true`. The connection is upgraded to TLS before any credentials are sent.

   In both cases, use the DC **hostname** that matches its certificate, and trust your internal CA. Run `node scripts/export-ad-ca.js`: it reads the enterprise root CA from AD into `certs/<CA>.pem` and prints its SHA-256 fingerprint. Check the fingerprint with `certutil -ca.cert`, then set `AD_CA_CERT_PATH=certs/<CA>.pem`. Without encryption, the portal refuses to change passwords and says why.
2. **Create the service account and admin group (automated).** As a Domain Admin, on a DC or a machine with RSAT:
   ```powershell
   .\scripts\setup-ad-service-account.ps1 -TargetOU "OU=Staff,DC=corp,DC=local" -WriteEnv
   ```
   This creates `svc-pwreset` (random password, never expires) and the `PasswordResetAdmins` group, delegates **only** *Reset Password*, *Read/Write pwdLastSet* and *Read lockoutTime* on user objects under `-TargetOU`, and with `-WriteEnv` writes `AD_BIND_DN`, a DPAPI-encrypted `AD_BIND_PASSWORD` and `AD_ADMIN_GROUP` into `.env`. Afterwards, deny interactive/RDP logon for `svc-pwreset` by GPO and add help-desk staff to the group. The manual equivalent is in steps 3 and 4.

   The portal checks the bind account at startup. If it's privileged (`adminCount=1`, e.g. Domain Admins), it warns in development and **refuses to start in production**.
3. **Delegate rights (manual alternative)** on the OUs that hold portal users. In *AD Users & Computers*, right-click the OU → *Delegate Control* → the service account → *Create a custom task* → *User objects*:
   - ✅ **Reset password**
   - ✅ Read/Write **pwdLastSet**
   - ✅ Read **lockoutTime**, **userAccountControl**, **memberOf**
   
   Do **not** delegate on privileged OUs such as Domain Admins or service accounts. Protected accounts (adminCount=1) are covered by AdminSDHolder and won't inherit this delegation anyway, which is intended.
4. **Create the admin group**, e.g. `CN=PasswordResetAdmins,OU=Groups,DC=corp,DC=local`, and add help-desk staff. Membership must be **direct**; nested groups aren't resolved.
5. Fill in `AD_*` in `.env`, set `AD_MOCK=false`, and restart.

### 5.1 Second domain (optional password sync)

If users have an account with the **same username** in a second domain (for example a separate mail domain), the portal can set the same password there on every change and reset, so no separate sync tool is needed.

1. In the second domain, create a least-privilege service account with the same delegation as in step 3. You can run `scripts/setup-ad-service-account.ps1` there, but **without** `-WriteEnv`, because that would overwrite the `AD_*` values.
2. Trust that domain's CA (`node scripts/export-ad-ca.js` with a temporary `.env` pointing at it, or copy its root CA PEM to `certs/`).
3. Set `AD2_URL`, `AD2_BIND_DN`, `AD2_BIND_PASSWORD` (then `.\scripts\protect-secret.ps1`), `AD2_USER_SEARCH_BASE`, `AD2_CA_CERT_PATH`, and optionally `AD_DOMAIN_LABEL` / `AD2_DOMAIN_LABEL` (e.g. `Desktop` / `Mail`). Restart.

**Without a certificate (`AD2_MODE=windows`).** When the second domain's DCs have no LDAPS certificate, a Windows portal server can write the password through Windows ADSI instead, the way *AD Users and Computers* does: Kerberos/NTLM sign-and-seal on port 389 (AD refuses password writes on connections that aren't encrypted). Skip step 2 and set:

```
AD2_MODE=windows
AD2_SERVER=dc01.mail.example      # a writable DC (nltest /dsgetdc:<domain> /writable), not an RODC
AD2_BIND_DN=MAIL\svc-pwreset      # or svc-pwreset@mail.example
AD2_BIND_PASSWORD=...             # then .\scripts\protect-secret.ps1
AD2_USER_SEARCH_BASE=             # optional, empty = whole domain
```

The portal server needs port 389 (and 88 for Kerberos) to that DC. Use its hostname so Kerberos is used: with an IP address or without a trust, Windows falls back to NTLM, which still encrypts the password but authenticates the DC less strongly than a certificate. Credentials and passwords reach the helper only through stdin. Keep PowerShell *Module Logging* (Group Policy, event 4103) turned off on the portal server: it records command arguments, which would include these passwords. Script block logging and transcription are fine.

How it behaves:
- Sign-in, the current-password check and admin rights use the **first** domain only.
- Before anything is written, the portal looks the user up in the second domain. If that domain can't be reached, **nothing is changed** and the user is asked to try again (a reset token stays valid).
- The first domain is written first, then the second. Users without an account in the second domain are skipped.
- Accounts are matched by username only, so the portal never writes a second-domain account that is disabled, protected (`adminCount=1`, e.g. Domain Admins) or the `AD2_BIND_DN` account itself. These are skipped like missing accounts, and the audit log records the reason.
- If the second domain rejects the password (for example because its policy is stricter), the first domain has already changed. The user is told that only one domain was updated and is asked to use *Forgot password* with a password that meets both policies. Each outcome is recorded in the audit log as `password_sync`.
- Use the same (or compatible) password policies in both domains to avoid partial changes.
- To check it works: the startup log shows `Sync to: <label> (...)`, and after a change the audit log has a `password_sync` entry `<label>: password updated`.

### 5.2 Mail: security alerts and expiry reminders (optional)

Set `SMTP_HOST`, `SMTP_PORT` and `MAIL_FROM`. An internal relay that accepts mail from the portal server's IP needs no login. Restart the portal; the startup log shows `Mail: <host>:<port>`. Then test with:

```powershell
node scripts/send-test-mail.js you@corp.example         # one short test message
node scripts/send-test-mail.js you@corp.example --all   # one sample of every mail users can get
```

`--all` builds each alert and reminder with the real templates and this server's settings (labels, `PORTAL_URL`, reminder stages), marks the subjects `[Sample]` and sends them only to the address you give, so you can review the formatting in your own mail client.

**Security alert.** After every successful password change or reset, the user gets a plain-text mail with the time, IP address, browser, the method used (change, or reset with questions / authenticator) and which domains were updated, plus "if this wasn't you, contact IT" and the portal address (`PORTAL_URL`). The portal address is the only link in any mail. The address is the user's `mail` attribute in the first domain. Users without one are skipped. The mail is sent after the response, so a slow relay never delays the user, and a mail failure never undoes a password change. Each outcome is audited as `notification`.

**Expiry reminders.** With `PASSWORD_REMINDERS=true`, the portal checks AD once a day from `PASSWORD_REMINDER_HOUR`. It mails every enabled user in `AD_USER_SEARCH_BASE` who has a `mail` address and a password that expires, once per stage (`PASSWORD_REMINDER_DAYS`, default 14 days before expiry and then every day over the last week: 7, 6, 5, 4, 3, 2 and 1 days). The expiry date is AD's own (`msDS-UserPasswordExpiryTimeComputed`), so the domain policy and fine-grained password policies apply. Users with *password never expires*, disabled accounts, and accounts that must change the password at next logon are skipped. Sent stages are recorded in `password_reminders`, so restarts never cause duplicates, and a new password starts a new cycle. A failed mail is retried at the next run. Each mail is audited as `password_reminder`.

**When only the second domain expires passwords** (for example a mail domain with a maximum password age while the sign-in domain has none), set `PASSWORD_REMINDER_SOURCE=secondary`. The expiry is then read from the second domain, but reminders still go only to users with an **enabled account in the first domain**, at that account's `mail` address. Second-domain accounts without a first-domain account, and accounts the sync never writes (disabled, `adminCount=1`, the `AD2_BIND_DN` account), get no reminder, because changing the password in the portal wouldn't help them. Whenever a second domain is configured, reminders point users to the portal only (Ctrl+Alt+Del would change just one domain).

**What users receive** (plain text, from `MAIL_FROM`; "Desktop"/"Mail" are `AD_DOMAIN_LABEL`/`AD2_DOMAIN_LABEL`, the sign-off uses `PORTAL_NAME`):

```
Subject: Your password was reset

Hello Jane Doe,

The password for your account "jdoe" was reset with "Forgot password" (verified with: authenticator app).

When:      12 Oct 2026, 14:05 (Europe/Berlin)
From IP:   192.0.2.10
Browser:   Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Updated:   Desktop, Mail

If this was you, no action is needed.
If this was NOT you, contact IT immediately: someone else may have access to your account.

Password portal: https://password.corp.example
```

```
Subject: Your Mail password expires in 7 days

Hello Jane Doe,

The Mail password for your account "jdoe" expires in 7 days, on Monday, 19 October 2026.
Please change it before then; after it expires you cannot sign in until it is reset.

Change it at https://password.corp.example (sign in, then choose Change Password).
This updates both your Desktop and Mail passwords.
```

A change while signed in says *was changed* instead of *was reset*, and the last reminder says *expires tomorrow*. Without a second domain, reminders say *Your password expires...* and also mention Ctrl+Alt+Del. Every mail ends with "Never share your password. IT will never ask for it by email or phone." and a do-not-reply line.

Before switching reminders on, see who would get one (nothing is sent):

```powershell
node scripts/password-reminders.js          # dry run
node scripts/password-reminders.js --send   # send now instead of waiting for the daily run
```

The dry run lists each user who is due (username, days left, address) and a summary. With `PASSWORD_REMINDER_SOURCE=secondary`, "checked" counts every second-domain account, because that's where the expiry is read. The summary then shows how many were skipped and why, e.g. `no Desktop account`, `Desktop account disabled`, `Mail: protected account (adminCount=1)`:

```
820 Mail account(s) checked (expiry read from Mail)
96 expire within 14 days and are not yet reminded
  -   41 skipped: no Desktop account
  -    3 skipped: Desktop account disabled
52 due (reminder goes to the Desktop mail address)
```

The service account only needs to read users (the default for domain users). Run `npm run db:init` once after upgrading, to create the `password_reminders` table.

## 6. PostgreSQL setup

Create a dedicated low-privilege user instead of using `postgres`:

```sql
-- run as postgres (e.g. in pgAdmin)
CREATE ROLE portal_user LOGIN PASSWORD 'change-me';
CREATE DATABASE ad_password_reset OWNER portal_user;
```

Then set `PG_USER=portal_user` and run `npm run db:init`. The schema is idempotent, and re-running it also applies new columns after an upgrade. For the integration tests, `portal_user` also needs `ALTER ROLE portal_user CREATEDB;`, or create `ad_password_reset_test` owned by `portal_user` yourself.

Tables: `users`, `security_questions`, `user_security_answers`, `audit_log`, `used_reset_tokens`, `password_exceptions`.

## 7. Intranet deployment (Windows Server)

### 7.0 Recommended topology

```
Browser --HTTPS 443--> IIS (SNI cert, HSTS, HTTP->HTTPS) --ARR--> Node 127.0.0.1:<port> --> AD (LDAPS/StartTLS) / PostgreSQL
```

- Node listens on `127.0.0.1` only (`HOST=127.0.0.1`, `TRUST_PROXY=loopback`) and its port is blocked in the firewall.
- A least-privilege DB role owns the database (no superuser rights).
- All secrets in `.env` are DPAPI **machine**-encrypted (`scripts\protect-secret.ps1 -Machine`); the TOTP key is also kept in a password vault.
- The install folder is restricted to Administrators and SYSTEM.
- A scheduled task (SYSTEM, at startup) keeps Node running.

Environment-specific installer scripts are not part of this repository. Sections 7.1–7.4 describe the manual setup.

### 7.1 Install
```powershell
# on the server (Node.js LTS installed)
cd D:\Apps\ad-sspr            # copy the project here (without node_modules and .env)
npm ci --omit=dev
Copy-Item .env.example .env   # fill in production values, NODE_ENV=production
npm run db:init
```
Restrict `.env` so only Administrators and the service identity can read it:
```powershell
icacls .env /inheritance:r /grant:r "Administrators:F" "NT AUTHORITY\SYSTEM:R"
```

### 7.2 HTTPS: choose one option
Create the certificate with `scripts/create-tls-cert.ps1`. It exports `certs/portal-tls.pfx` (git-ignored) and writes `TLS_PFX_PATH` and a DPAPI-encrypted `TLS_PFX_PASSPHRASE` to `.env`:
```powershell
# Production: certificate from your enterprise CA (AD CS "WebServer" template)
.\scripts\create-tls-cert.ps1 -Mode Ca -DnsName password.corp.local -CAConfig "CA01.corp.local\Corp-Root-CA"
# Development: self-signed for localhost + this computer
.\scripts\create-tls-cert.ps1
```
A self-signed dev certificate shows a browser warning. To trust it on your own PC, open `certmgr.msc`, then copy the *AD SSPR portal (dev)* certificate from *Personal* into *Trusted Root Certification Authorities*. A CA-issued certificate is trusted automatically on domain PCs. Set `HTTP_REDIRECT_PORT=80` to redirect plain-HTTP visitors.
- **Option A: native HTTPS (simplest).** Request a web server certificate from your internal CA for e.g. `password.corp.local`, export it as PFX, then set `TLS_PFX_PATH`, `TLS_PFX_PASSPHRASE` and `PORT=443`. Keep `TRUST_PROXY=false`.
- **Option B: IIS reverse proxy.** Install *URL Rewrite* and *ARR* and enable the proxy in ARR. Bind the certificate to the IIS site and add a rewrite rule `(.*)` → `http://localhost:3000/{R:1}`. Set `TRUST_PROXY=loopback` and keep Node on HTTP, bound to localhost only (firewall port 3000).

### 7.3 Run in the background
Use a scheduled task instead of a Windows service (no third-party tools needed) that runs `node server\server.js` as SYSTEM at startup, restarts on exit, and writes to a log file:
```powershell
Get-ScheduledTask '<task name>'                                       # status
Stop-ScheduledTask '<task name>'; Start-ScheduledTask '<task name>'   # restart
Get-Content <install folder>\logs\portal.log -Tail 50 -Wait           # live log
```
[NSSM](https://nssm.cc) works as well if you prefer a real service: point it at `node.exe server\server.js` with `AppDirectory` set to the install folder.

### 7.4 Network and DNS
- DNS A record matching the certificate.
- Firewall: inbound 443 and 80 (redirect only) from client subnets; the Node port stays blocked; outbound 389 (StartTLS) or 636 to the DC; PostgreSQL local only.
- Optional: publish the URL in the Windows logon screen or intranet home page, so locked-out users can find it from a colleague's PC or a kiosk.

### 7.5 Production checklist
- [ ] `NODE_ENV=production`, `AD_MOCK=false`, `HOST=127.0.0.1`, `TRUST_PROXY=loopback`
- [ ] New random `JWT_SECRET` and `TOTP_ENCRYPTION_KEY`, DPAPI machine-encrypted
- [ ] `TOTP_ENCRYPTION_KEY` stored in the password vault
- [ ] Encrypted AD connection (LDAPS or StartTLS) with the CA verified (`AD_TLS_REJECT_UNAUTHORIZED=true`)
- [ ] HTTPS in IIS with HSTS, HTTP redirects to HTTPS, `X-Powered-By` hidden
- [ ] Dedicated DB role (no superuser rights)
- [ ] Regular DB backups (§13)
- [ ] Least-privilege AD service account (production refuses privileged accounts)
- [ ] Install folder and `.env` restricted to Administrators + SYSTEM
- [ ] DNS record created; PFX file deleted after import; `postgres` password rotated
- [ ] Optional mail: test mail sent (`scripts/send-test-mail.js`), reminder dry run checked before `PASSWORD_REMINDERS=true`
- [ ] End-user test from a domain PC (sign in, enroll, reset, admin page)

## 8. User guide

1. **First sign-in:** open the portal and sign in with your domain username (just the username, not your email address or `DOMAIN\username`) and password. You're taken straight to enrollment.
2. **Enroll:**
   - Step 1: pick 3 different questions and type answers (not case-sensitive).
   - Step 2: scan the QR code with Google Authenticator, Microsoft Authenticator or a compatible app (if none is installed, download one from the Google Play Store or the App Store), then type the 6-digit code.
3. **Forgot your password:** on the sign-in page click *Reset it here* and enter your username. With the default policy (`RESET_POLICY=both`), answer your security questions, **then** enter the 6-digit code from your authenticator app. Then choose a new password within 10 minutes. If you've lost your phone, contact the help desk; they can reset your enrollment.
4. **Change password:** after signing in, go to *Change Password*. It appears only once you've finished enrollment (security questions and authenticator app). You're signed out afterwards and sign in again with the new password.
5. **Security Settings** (shown in the navigation bar once you've enrolled):
   - **Update questions or answers:** your current questions are pre-selected. Answers are stored as one-way hashes and can't be shown to anyone, so leave an answer blank to keep it, or type a new one.
   - **Replace authenticator (new device):** scan the new QR code and enter a code from the new device. Your old device keeps working until the new one is verified, then stops working.
6. **Emails** (if your organization turned them on): after every password change or reset you get an email with the time, IP address and browser. If you didn't make the change, contact IT immediately. Before your password expires you get reminders (by default 14, 7, 3 and 1 days before). Change your password in the portal when you get one.
7. **Password rules:** at least 8 characters, with 3 of these 4: uppercase, lowercase, number, symbol. It can't contain your username, and your domain policy may block recently used passwords.

## 9. Admin guide

Members of `AD_ADMIN_GROUP` and portal admins see **Admin** in the navigation bar.
- **Stats:** total, enrolled, pending and locked users (users appear once they've signed in for the first time).
- **Users:** search and filter. **Lock** blocks sign-in and self-service reset and revokes the user's sessions; **Unlock** restores access. **Reset Enrollment** deletes their answers and authenticator, which you'd use for a lost phone. They must enroll again at their next sign-in.
- **Portal admins:** **+ Add Admin** grants admin rights by AD username (the account must exist and be enabled; it doesn't need to have signed in yet). **Make Admin** / **Remove Admin** on a user row does the same for existing users, and the *Portal Admins* filter lists them. Changes apply immediately, without signing in again, and are audited (*Admin granted*, *Admin removed*). You can't remove your own rights, and locking a portal admin also blocks their admin access. Members of `AD_ADMIN_GROUP` are always admins and can't be removed here.
- **Audit Log:** filter by exact username, action and date range. Every sign-in, reset attempt, enrollment and admin action is recorded with IP and user agent, and so is every alert and reminder mail (*Password alert mail*, *Expiry reminder mail*), including failures.
- **Security Questions:** add, edit, reorder, deactivate. Deactivating a question hides it from new enrollments; existing users keep it.
- **Password Exceptions:** words or phrases that new passwords (change and reset) may not use. *Contains* blocks any password that includes the entry; *Exact* blocks only that exact password. Matching ignores case and common look-alikes (`@`→a, `0`→o, `1`→i/l, `3`→e, `$`/`5`→s, `7`→t, `4`→a), so `company` also blocks `C0mp@ny2026`. Entries can be edited, deactivated or removed and apply immediately, in addition to the domain password policy.

Help-desk procedure for a user who lost their phone: check the user's identity by your normal process → **Reset Enrollment** → the user signs in (or you reset the AD password in ADUC) → the user enrolls again.

## 10. Security model

| Threat | Control |
|---|---|
| Password theft from the database | Passwords are never stored; all operations go to AD over LDAPS |
| Database leak | Answers hashed with bcrypt (cost 12) and normalized (trim + lowercase); TOTP secrets encrypted with AES-256-GCM |
| Brute force | Per IP+username rate limit (5 per 15 min; authenticator QR generation has a separate, looser limit); account lockout after 5 failed verifications (30 min); generic error messages |
| User enumeration | Unknown and not-enrolled users get the same response; login errors don't reveal whether the user exists |
| Reset token replay | Single-use JWT (10 min) claimed atomically in `used_reset_tokens`; forged or wrong-type tokens rejected |
| TOTP code replay | Last accepted time step stored per user; a code can't be reused, including the one entered at enrollment |
| Security question bypass | Every stored question must be answered exactly once |
| Weak security questions | `RESET_POLICY=both` (default) requires questions **and** a TOTP code. The questions step only yields a 5-minute step token bound to that user, which is useless as a session or reset token. |
| Secrets in config files | `.env` secrets DPAPI-encrypted (`protect-secret.ps1`); PFX private key protected by a random DPAPI-encrypted passphrase and git-ignored |
| Over-privileged service account | Least-privilege account script; startup detects `adminCount=1` accounts (warning in development, refusal in production) |
| Stolen session | 15-min access tokens; refresh tokens revoked on logout and on admin lock (`token_version`) |
| Stale admin rights | Portal-granted admin rights are re-checked in the database on every admin request, so removing them or locking the user applies immediately; every grant and removal is audited |
| Token misuse | Access, refresh and reset tokens are typed; only `access` tokens open a session; algorithm pinned to HS256 |
| Factor takeover via a stolen session | Changing existing security answers or replacing the authenticator requires the current AD password (rate-limited) |
| Clear-text passwords on the network | The AD connection must be encrypted (startup refuses plain `ldap://`); production refuses to start without HTTPS or `TRUST_PROXY`; optional `PG_SSL` |
| Passwords in logs | Unknown "usernames" (often mistyped passwords) are logged as `(unknown user)`; malformed request bodies are never logged or echoed; `Cache-Control: no-store` on all API responses |
| Security question visibility | Answers exist only as bcrypt hashes and are never returned by any endpoint (covered by a test); unknown or unenrolled accounts get stable decoy questions and the same errors and timing as wrong answers |
| XSS | Strict CSP (`script-src 'self'`, no inline scripts); all dynamic content escaped or set with `textContent` |
| SQL injection | Parameterized queries only (covered by a test) |
| Second-domain account takeover by name | Sync never writes a second-domain account that is disabled, protected (`adminCount=1`) or the `AD2_BIND_DN` account; the second domain is looked up before anything is written, and every outcome is audited (`password_sync`) |
| Secrets passed to the Windows helper | `AD2_MODE=windows` sends credentials and passwords to PowerShell over stdin only (never the command line), and the connection is sealed (sign-and-seal); keep PowerShell *Module Logging* (event 4103) disabled on the portal server, because it would record command arguments |
| Password change you didn't make | Optional alert mail after every change and reset (time, IP, browser); mails never contain a password, and the only link is the portal's own address |
| Misconfiguration | Production refuses to start with a weak or missing `JWT_SECRET`/`TOTP_ENCRYPTION_KEY` or with `AD_MOCK` |

## 11. API reference

All responses have the shape `{ success, data?, message? }`. Authenticated calls need `Authorization: Bearer <token>`.

| Method | Path | Auth | Body / query |
|---|---|---|---|
| POST | `/api/auth/login` | – | `{ username, password }` |
| POST | `/api/auth/refresh` | – | `{ refreshToken }` |
| GET | `/api/auth/me` | user | – |
| POST | `/api/auth/logout` | user | – |
| GET | `/api/enrollment/questions` | user | – |
| GET | `/api/enrollment/security-questions` | user | – → current `[{ questionId, questionText }]` (no answers) |
| POST | `/api/enrollment/security-questions` | user | `{ answers: [{ questionId, answer }] ×3, currentPassword? }`. An empty `answer` keeps the saved one; `currentPassword` is required once questions exist. |
| POST | `/api/enrollment/totp/setup` | user | `{ currentPassword? }` (required when an authenticator is already active) → `{ qrCode, secret }` (staged as pending; the current device stays active) |
| POST | `/api/enrollment/totp/verify` | user | `{ code }` from the new device; activates it and retires the old one |
| GET | `/api/enrollment/status` | user | – |
| POST | `/api/password/change` | user | `{ currentPassword, newPassword, confirmPassword }`. Enrolled users only; otherwise 403 with `code: 'ENROLLMENT_REQUIRED'`. |
| POST | `/api/password/reset/verify-user` | – | `{ username }` → `availableMethods` |
| POST | `/api/password/reset/get-questions` | – | `{ username }` |
| POST | `/api/password/reset/verify-questions` | – | `{ username, answers }` → `resetToken` (`either`) or `stepToken` + `nextStep: 'totp'` (`both`) |
| POST | `/api/password/reset/verify-totp` | – | `{ username, code, stepToken? }` → `resetToken` (`stepToken` required under `both`) |
| POST | `/api/password/reset/set-password` | – | `{ resetToken, newPassword, confirmPassword }` |
| GET | `/api/admin/users` | admin | `?page&limit&search&filter=all\|enrolled\|pending\|locked\|admins` |
| PUT | `/api/admin/users/:id/lock` | admin | `{ locked: boolean }` |
| PUT | `/api/admin/users/:id/reset-enrollment` | admin | – |
| PUT | `/api/admin/users/:id/admin` | admin | `{ isAdmin: boolean }` (your own rights can't be removed) |
| POST | `/api/admin/admins` | admin | `{ username }` (enabled AD account) |
| GET | `/api/admin/stats` | admin | – |
| GET | `/api/admin/audit-log` | admin | `?page&limit&username&action&startDate&endDate` |
| GET/POST | `/api/admin/questions` | admin | POST `{ questionText, sortOrder? }` |
| PUT | `/api/admin/questions/:id` | admin | `{ questionText?, isActive?, sortOrder? }` |
| GET/POST | `/api/admin/password-exceptions` | admin | POST `{ term, matchType?: 'contains'\|'exact' }` |
| PUT/DELETE | `/api/admin/password-exceptions/:id` | admin | PUT `{ term?, matchType?, isActive? }` |

## 12. Testing

```powershell
npm run test:unit          # no database needed
npm run test:integration   # uses <PG_DATABASE>_test, created automatically
npm test                   # everything (99 tests)
```
The integration tests start the app on a random port with the mock AD and reset the test database before each test. They refuse to run against a database whose name doesn't end in `_test`.

## 13. Maintenance & operations

- **Expired reset tokens** are removed automatically every hour; reminder records 30 days after the expiry date they belong to.
- **Audit log retention:** decide on a retention period and schedule e.g. `DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '1 year';`
- **Backups:** daily `pg_dump -h localhost -U postgres -Fc <database> > portal.dump`. Keep the `TOTP_ENCRYPTION_KEY` in your vault: a machine-encrypted `.env` can't be restored on another server.
- **Upgrades:** copy the new files to the install folder (never overwrite `.env`), run `npm ci --omit=dev` and `npm run db:init` (applies schema changes), then restart the portal.
- **Logs:** security events are in the `audit_log` table and the admin page.
- **Rotate the service-account password:** reset it in AD, then run `.\scripts\protect-secret.ps1 -Name AD_BIND_PASSWORD` (add `-Machine` for LocalSystem) and restart the portal.

## 14. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `LDAP connection error ... self signed / unable to verify` | Node doesn't trust your internal CA. Run `node scripts/export-ad-ca.js` and set `AD_CA_CERT_PATH` (or set the system environment variable `NODE_EXTRA_CA_CERTS`), then restart. |
| `Directory server unreachable: connection timed out` | The port is blocked or the service isn't listening (common: 636 closed). Check with `Test-NetConnection <dc> -Port 636`, or use 389 with `AD_STARTTLS=true`. |
| `Hostname/IP does not match certificate` | `AD_URL` uses an IP address. Use the DC hostname, or set `AD_TLS_SERVERNAME`. |
| `password changes require LDAPS or AD_STARTTLS=true` | `AD_URL` is plain `ldap://` without StartTLS. |
| Portal stops right after start (reverse proxy shows 502) after adding `AD2_*` settings | Startup refuses incomplete second-domain settings (`AD2_MODE=windows` needs `AD2_SERVER`, `AD2_BIND_DN`, `AD2_BIND_PASSWORD`) and, in production, a privileged `AD2_BIND_DN`. The log shows the reason. Comment out `AD2_MODE`/`AD2_SERVER` to start without the sync, then fix the settings. |
| No `Sync to:` line in the startup log | The second domain is disabled: `AD2_URL` (ldap mode) or `AD2_SERVER` (windows mode) is not set, or commented out. |
| `... is a read-only domain controller; set AD2_SERVER to a writable DC` | `AD2_SERVER` points at an RODC. Find a writable DC with `nltest /dsgetdc:<domain> /writable`. |
| `Failed to change password: ... 00002077` / unwilling to perform | Password writes need LDAPS. Check `AD_URL` starts with `ldaps://`. |
| Password change fails with an access error | The service account lacks the *Reset password* delegation on that OU, or the user is protected by AdminSDHolder. |
| "does not meet the domain password policy" | AD rejected the password (length, complexity, history, or minimum password age). |
| Admin menu missing | The user isn't a **direct** member of `AD_ADMIN_GROUP` (or the DN is wrong) and isn't a portal admin. Sign out and in again after fixing the group; portal-admin changes apply immediately. |
| Everyone gets rate-limited | Clients share one IP (proxy or NAT). Set `TRUST_PROXY` correctly and/or raise `RATE_LIMIT_GENERAL_MAX`. |
| Authenticator codes always invalid | The server clock is wrong. Keep the server synced to the domain time source (`w32tm /resync`). |
| Server exits: `JWT_SECRET must be set...` | Production startup check: set strong secrets in `.env`. |
| `FATAL: AD_BIND_DN ... is a privileged account (adminCount=1)` | Production refuses Domain Admin (or similar) bind accounts. Use a least-privilege account (`scripts\setup-ad-service-account.ps1` creates one), then restart the portal. |
| IIS returns **502** | Node isn't running behind IIS. Check the portal log and the scheduled task. |
| "Current password is incorrect" right after a failed change | The password may already have been changed by the earlier attempt. Compare the user's `pwdLastSet` in AD with the audit log (`password_change` entries). The user should sign in with the **new** password. |
| `Failed to change password: ... closed` | The LDAP connection closed before AD replied. Make sure the server runs the current `server/services/ldapService.js`. |
| No alert or reminder arrives | Check the audit log (`notification` / `password_reminder` rows show the reason), then `node scripts/send-test-mail.js <address>`. The user's AD account needs a `mail` attribute. |
| Mail fails with `self signed certificate` / `unable to verify` | The relay offers STARTTLS with a certificate Node doesn't trust. Set `SMTP_CA_CERT_PATH` to its CA, or (self-signed relay only) `SMTP_TLS_REJECT_UNAUTHORIZED=false`. |
| Mail fails with `5.7.1` / relay denied | The relay doesn't accept mail from the portal server. Allow the server's IP on the relay connector, or use `SMTP_USER`/`SMTP_PASSWORD`. |
| `Cannot decrypt <NAME>` at startup | The `.env` was encrypted on another machine or by another account. Re-enter the value with `scripts\protect-secret.ps1 -Machine` on this server. |
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope Process Bypass` in that PowerShell window first. |

## 15. Known limitations

- **DPAPI scope:** CurrentUser-encrypted secrets can only be decrypted by that Windows account, and machine scope only on that server. Anyone who can run code as that account on that server can still read them. Protect the server itself.
- **Knowing whether an account is enrolled:** `verify-user` has to tell an enrolled user which methods are available, so it reveals whether an account is enrolled. This is limited by rate limiting.
- **Password history on reset:** the service account sets the password with an admin reset (`replace unicodePwd`). AD **doesn't enforce password history** for admin resets; length and complexity are still enforced. The same applies to *Change Password*, where the current password is checked with an extra bind first.
- **Nested groups** aren't resolved for admin membership.
- **Access tokens** stay valid for up to 15 minutes after logout or lock; refresh tokens are revoked immediately.
- **Password changes outside the portal** (AD Users & Computers, Ctrl+Alt+Del) don't end existing portal sessions. After *Change Password* in the portal, the browser signs the user out.
- **Users appear in the admin list** only after their first sign-in to the portal.
- **Second domain:** the two domains can't be updated atomically. If the second domain rejects a password the first already accepted, the domains differ until the user resets again (see §5.1). Passwords changed outside the portal aren't synced.

## License

Released under the [MIT License](LICENSE).
