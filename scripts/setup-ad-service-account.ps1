<#
.SYNOPSIS
    Creates a least-privilege AD service account and the portal admin group, and delegates
    only the rights the portal needs. Run once as a Domain Admin (on a DC or with RSAT dsacls.exe).

.DESCRIPTION
    - Creates user  <AccountName> in <AccountOU>  (random 32-char password, never expires,
      cannot change password; interactive logon should be denied by GPO).
    - Creates group <AdminGroupName> in <GroupOU> (add help-desk staff to it).
    - Delegates on <TargetOU> for descendant user objects:
        Reset Password (extended right), Read/Write pwdLastSet, Read lockoutTime.
      Protected accounts (adminCount=1, e.g. Domain Admins) are excluded by AdminSDHolder by design.
    - Prints the new password ONCE, encrypted for .env if you pass -WriteEnv.

.EXAMPLE
    .\scripts\setup-ad-service-account.ps1 -TargetOU "OU=Staff,DC=corp,DC=example"
    .\scripts\setup-ad-service-account.ps1 -TargetOU "CN=Users,DC=corp,DC=example" -WriteEnv
#>
param(
    [Parameter(Mandatory)] [string]$TargetOU,
    [string]$AccountName = 'svc-pwreset',
    [string]$AccountOU,
    [string]$AdminGroupName = 'PasswordResetAdmins',
    [string]$GroupOU,
    [switch]$WriteEnv
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command dsacls.exe -ErrorAction SilentlyContinue)) {
    throw 'dsacls.exe not found. Run on a domain controller or install RSAT: AD DS tools.'
}

$root = [ADSI]'LDAP://RootDSE'
$domainDN = $root.defaultNamingContext
$netbios = $env:USERDOMAIN
if (-not $AccountOU) { $AccountOU = "CN=Users,$domainDN" }
if (-not $GroupOU) { $GroupOU = "CN=Users,$domainDN" }

# --- Service account ---
$accountDN = "CN=$AccountName,$AccountOU"
$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes) + 'a1!'

if ([ADSI]::Exists("LDAP://$accountDN")) {
    Write-Host "Account exists: $accountDN (password will be reset)"
    $user = [ADSI]"LDAP://$accountDN"
} else {
    $user = ([ADSI]"LDAP://$AccountOU").Create('user', "CN=$AccountName")
    $user.Put('sAMAccountName', $AccountName)
    $user.Put('description', 'AD Self-Service Password Reset portal (least privilege)')
    $user.SetInfo()
    Write-Host "Created account: $accountDN"
}
$user.SetPassword($password)
# NORMAL_ACCOUNT (512) + DONT_EXPIRE_PASSWORD (65536)
$user.Put('userAccountControl', 66048)
$user.SetInfo()

# --- Admin group ---
$groupDN = "CN=$AdminGroupName,$GroupOU"
if (-not [ADSI]::Exists("LDAP://$groupDN")) {
    $group = ([ADSI]"LDAP://$GroupOU").Create('group', "CN=$AdminGroupName")
    $group.Put('sAMAccountName', $AdminGroupName)
    $group.Put('description', 'Admins of the AD Self-Service Password Reset portal')
    $group.SetInfo()
    Write-Host "Created group: $groupDN"
} else {
    Write-Host "Group exists: $groupDN"
}

# --- Delegation (descendant user objects only) ---
$principal = "$netbios\$AccountName"
& dsacls.exe $TargetOU /I:S /G "${principal}:CA;Reset Password;user" | Out-Null
& dsacls.exe $TargetOU /I:S /G "${principal}:RPWP;pwdLastSet;user" | Out-Null
& dsacls.exe $TargetOU /I:S /G "${principal}:RP;lockoutTime;user" | Out-Null
Write-Host "Delegated Reset Password / pwdLastSet / lockoutTime on $TargetOU to $principal"

Write-Host ''
Write-Host 'Update .env:'
Write-Host "  AD_BIND_DN=$accountDN"
Write-Host "  AD_ADMIN_GROUP=$groupDN"
if ($WriteEnv) {
    $envFile = Join-Path $PSScriptRoot '..\.env'
    $lines = [Collections.Generic.List[string]](Get-Content $envFile)
    $protected = 'dpapi:' + (ConvertFrom-SecureString (ConvertTo-SecureString $password -AsPlainText -Force))
    foreach ($pair in @(@('AD_BIND_DN', $accountDN), @('AD_BIND_PASSWORD', $protected), @('AD_ADMIN_GROUP', $groupDN))) {
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*$($pair[0])=") { $lines[$i] = "$($pair[0])=$($pair[1])"; $found = $true }
        }
        if (-not $found) { $lines.Add("$($pair[0])=$($pair[1])") }
    }
    [IO.File]::WriteAllLines((Resolve-Path $envFile), $lines)
    Write-Host '  (written to .env; AD_BIND_PASSWORD is DPAPI-encrypted for the current Windows user)'
} else {
    Write-Host "  AD_BIND_PASSWORD=$password"
    Write-Host '  -> then run .\scripts\protect-secret.ps1 to encrypt it'
}
Write-Host "Add help-desk staff to $AdminGroupName, and deny interactive/RDP logon for $AccountName by GPO."
