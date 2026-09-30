# AD Self-Service Password Reset Portal

An **intranet** web portal that lets Active Directory users change their password and reset a forgotten password on their own. Users prove who they are with **security questions** or an **authenticator app (TOTP)**. Help-desk staff get an admin panel for enrollment tracking, account locking and an audit trail.

- Backend: Node.js 18+ (tested on 24), Express 5, `ldapjs`, PostgreSQL
- Frontend: plain HTML/CSS/JS with no build step and no external CDN or font requests, so it works on isolated networks
- Tests: 65 automated tests (`node:test`)

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
| Change password | For signed-in users. The current password is checked against AD. |
| Admin panel | Enrollment stats, user search and filters, lock/unlock, enrollment reset, audit log viewer, security question management, password exception list (blocked words). |
| Security | Rate limiting, account lockout, TOTP replay protection, refresh-token revocation, audit log, CSP/Helmet. |

## 2. Architecture

```
Browser ──HTTPS──► Express (Node.js) ──LDAPS 636──► Active Directory
                        │
                        └──TCP 5432──► PostgreSQL (enrollment, answers, TOTP secrets, audit)
```

- **Passwords are never stored.** Every password operation goes straight to AD.
- **Admin rights** come from membership in the AD group set in `AD_ADMIN_GROUP`.
- Layout: `server/` (config, controllers, middleware, routes, services, db/schema.sql), `public/` (pages and scripts), `scripts/init-db.js`, `test/`.

## 3. Quick start (development)

Prerequisites: Node.js 18+ and PostgreSQL 13+.

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
| `AD_ALLOW_PRIVILEGED_BIND` | `false` | Production refuses to start if `AD_BIND_DN` is privileged (adminCount=1). Temporary override only. |

### Encrypting secrets in `.env`
Run `.\scripts\protect-secret.ps1` to encrypt every plain-text secret in `.env` (`AD_BIND_PASSWORD`, `PG_PASSWORD`, `JWT_SECRET`, `TOTP_ENCRYPTION_KEY`, `TLS_PFX_PASSPHRASE`) with **Windows DPAPI**. Values become `dpapi:…` and are decrypted in memory at startup.
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
- [ ] End-user test from a domain PC (sign in, enroll, reset, admin page)

## 8. User guide

1. **First sign-in:** open the portal and sign in with your Windows username and password. You're taken straight to enrollment.
2. **Enroll:**
   - Step 1: pick 3 different questions and type answers (not case-sensitive).
   - Step 2: scan the QR code with Microsoft Authenticator, Google Authenticator or a similar app, then type the 6-digit code.
3. **Forgot your password:** on the sign-in page click *Reset it here* and enter your username. With the default policy (`RESET_POLICY=both`), answer your security questions, **then** enter the 6-digit code from your authenticator app. Then choose a new password within 10 minutes. If you've lost your phone, contact the help desk; they can reset your enrollment.
4. **Change password:** after signing in, go to *Change Password*. You're signed out afterwards and sign in again with the new password.
5. **Security Settings** (shown in the navigation bar once you've enrolled):
   - **Update questions or answers:** your current questions are pre-selected. Answers are stored as one-way hashes and can't be shown to anyone, so leave an answer blank to keep it, or type a new one.
   - **Replace authenticator (new device):** scan the new QR code and enter a code from the new device. Your old device keeps working until the new one is verified, then stops working.
6. **Password rules:** at least 8 characters, with 3 of these 4: uppercase, lowercase, number, symbol. It can't contain your username, and your domain policy may block recently used passwords.

## 9. Admin guide

Members of `AD_ADMIN_GROUP` see **Admin** in the navigation bar.
- **Stats:** total, enrolled, pending and locked users (users appear once they've signed in for the first time).
- **Users:** search and filter. **Lock** blocks sign-in and self-service reset and revokes the user's sessions; **Unlock** restores access. **Reset Enrollment** deletes their answers and authenticator, which you'd use for a lost phone. They must enroll again at their next sign-in.
- **Audit Log:** filter by exact username, action and date range. Every sign-in, reset attempt, enrollment and admin action is recorded with IP and user agent.
- **Security Questions:** add, edit, reorder, deactivate. Deactivating a question hides it from new enrollments; existing users keep it.
- **Password Exceptions:** words or phrases that new passwords (change and reset) may not use. *Contains* blocks any password that includes the entry; *Exact* blocks only that exact password. Matching ignores case and common look-alikes (`@`→a, `0`→o, `1`→i/l, `3`→e, `$`/`5`→s, `7`→t, `4`→a), so `company` also blocks `C0mp@ny2026`. Entries can be edited, deactivated or removed and apply immediately, in addition to the domain password policy.

Help-desk procedure for a user who lost their phone: check the user's identity by your normal process → **Reset Enrollment** → the user signs in (or you reset the AD password in ADUC) → the user enrolls again.

## 10. Security model

| Threat | Control |
|---|---|
| Password theft from the database | Passwords are never stored; all operations go to AD over LDAPS |
| Database leak | Answers hashed with bcrypt (cost 12) and normalized (trim + lowercase); TOTP secrets encrypted with AES-256-GCM |
| Brute force | Per IP+username rate limit (5 per 15 min); account lockout after 5 failed verifications (30 min); generic error messages |
| User enumeration | Unknown and not-enrolled users get the same response; login errors don't reveal whether the user exists |
| Reset token replay | Single-use JWT (10 min) claimed atomically in `used_reset_tokens`; forged or wrong-type tokens rejected |
| TOTP code replay | Last accepted time step stored per user; a code can't be reused, including the one entered at enrollment |
| Security question bypass | Every stored question must be answered exactly once |
| Weak security questions | `RESET_POLICY=both` (default) requires questions **and** a TOTP code. The questions step only yields a 5-minute step token bound to that user, which is useless as a session or reset token. |
| Secrets in config files | `.env` secrets DPAPI-encrypted (`protect-secret.ps1`); PFX private key protected by a random DPAPI-encrypted passphrase and git-ignored |
| Over-privileged service account | Least-privilege account script; startup detects `adminCount=1` accounts (warning in development, refusal in production) |
| Stolen session | 15-min access tokens; refresh tokens revoked on logout and on admin lock (`token_version`) |
| Token misuse | Access, refresh and reset tokens are typed; only `access` tokens open a session; algorithm pinned to HS256 |
| Factor takeover via a stolen session | Changing existing security answers or replacing the authenticator requires the current AD password (rate-limited) |
| Clear-text passwords on the network | The AD connection must be encrypted (startup refuses plain `ldap://`); production refuses to start without HTTPS or `TRUST_PROXY`; optional `PG_SSL` |
| Passwords in logs | Unknown "usernames" (often mistyped passwords) are logged as `(unknown user)`; malformed request bodies are never logged or echoed; `Cache-Control: no-store` on all API responses |
| Security question visibility | Answers exist only as bcrypt hashes and are never returned by any endpoint (covered by a test); unknown or unenrolled accounts get stable decoy questions and the same errors and timing as wrong answers |
| XSS | Strict CSP (`script-src 'self'`, no inline scripts); all dynamic content escaped or set with `textContent` |
| SQL injection | Parameterized queries only (covered by a test) |
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
| POST | `/api/password/change` | user | `{ currentPassword, newPassword, confirmPassword }` |
| POST | `/api/password/reset/verify-user` | – | `{ username }` → `availableMethods` |
| POST | `/api/password/reset/get-questions` | – | `{ username }` |
| POST | `/api/password/reset/verify-questions` | – | `{ username, answers }` → `resetToken` (`either`) or `stepToken` + `nextStep: 'totp'` (`both`) |
| POST | `/api/password/reset/verify-totp` | – | `{ username, code, stepToken? }` → `resetToken` (`stepToken` required under `both`) |
| POST | `/api/password/reset/set-password` | – | `{ resetToken, newPassword, confirmPassword }` |
| GET | `/api/admin/users` | admin | `?page&limit&search&filter=all\|enrolled\|pending\|locked` |
| PUT | `/api/admin/users/:id/lock` | admin | `{ locked: boolean }` |
| PUT | `/api/admin/users/:id/reset-enrollment` | admin | – |
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
npm test                   # everything (65 tests)
```
The integration tests start the app on a random port with the mock AD and reset the test database before each test. They refuse to run against a database whose name doesn't end in `_test`.

## 13. Maintenance & operations

- **Expired reset tokens** are removed automatically every hour.
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
| `Failed to change password: ... 00002077` / unwilling to perform | Password writes need LDAPS. Check `AD_URL` starts with `ldaps://`. |
| Password change fails with an access error | The service account lacks the *Reset password* delegation on that OU, or the user is protected by AdminSDHolder. |
| "does not meet the domain password policy" | AD rejected the password (length, complexity, history, or minimum password age). |
| Admin menu missing | The user isn't a **direct** member of `AD_ADMIN_GROUP`, or the DN is wrong. Sign out and in again after fixing it. |
| Everyone gets rate-limited | Clients share one IP (proxy or NAT). Set `TRUST_PROXY` correctly and/or raise `RATE_LIMIT_GENERAL_MAX`. |
| Authenticator codes always invalid | The server clock is wrong. Keep the server synced to the domain time source (`w32tm /resync`). |
| Server exits: `JWT_SECRET must be set...` | Production startup check: set strong secrets in `.env`. |
| `FATAL: AD_BIND_DN ... is a privileged account (adminCount=1)` | Production refuses Domain Admin (or similar) bind accounts. Use a least-privilege account (`scripts\setup-ad-service-account.ps1` creates one), then restart the portal. |
| IIS returns **502** | Node isn't running behind IIS. Check the portal log and the scheduled task. |
| "Current password is incorrect" right after a failed change | The password may already have been changed by the earlier attempt. Compare the user's `pwdLastSet` in AD with the audit log (`password_change` entries). The user should sign in with the **new** password. |
| `Failed to change password: ... closed` | The LDAP connection closed before AD replied. Make sure the server runs the current `server/services/ldapService.js`. |
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
