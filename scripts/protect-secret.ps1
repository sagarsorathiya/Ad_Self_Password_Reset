<#
.SYNOPSIS
    Encrypts secrets in .env with Windows DPAPI so they are not stored in clear text.

.DESCRIPTION
    Without -Name: encrypts every secret in .env that is still plain text
    (AD_BIND_PASSWORD, PG_PASSWORD, JWT_SECRET, TOTP_ENCRYPTION_KEY, TLS_PFX_PASSPHRASE).
    With -Name: prompts (hidden input) for one value and writes it encrypted.

    Scope:
      default   CurrentUser  - run this as the SAME Windows account that runs the portal/service.
      -Machine  LocalMachine - any process on this server can decrypt (use for LocalSystem services).
    Values encrypted on one server/account cannot be decrypted elsewhere: keep a copy of
    TOTP_ENCRYPTION_KEY in your password vault, or all users must re-enroll if it is lost.

.EXAMPLE
    .\scripts\protect-secret.ps1                       # protect all plain-text secrets in .env
    .\scripts\protect-secret.ps1 -Name AD_BIND_PASSWORD # set a new value (prompted, hidden)
    .\scripts\protect-secret.ps1 -Machine              # machine scope for a LocalSystem service
#>
param(
    [string]$Name,
    [switch]$Machine,
    [string]$EnvFile = (Join-Path $PSScriptRoot '..\.env')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$secretKeys = 'AD_BIND_PASSWORD', 'PG_PASSWORD', 'JWT_SECRET', 'TOTP_ENCRYPTION_KEY', 'TLS_PFX_PASSPHRASE'

function Protect([string]$plain) {
    if ($Machine) {
        $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
        return 'dpapi-machine:' + [Convert]::ToBase64String(
            [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'LocalMachine'))
    }
    return 'dpapi:' + (ConvertFrom-SecureString (ConvertTo-SecureString $plain -AsPlainText -Force))
}

if (-not (Test-Path $EnvFile)) { throw ".env not found at $EnvFile" }
$lines = [Collections.Generic.List[string]](Get-Content $EnvFile)

function Set-Value([string]$key, [string]$protected) {
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "^\s*$key=") { $idx = $i } }
    if ($idx -ge 0) { $lines[$idx] = "$key=$protected" } else { $lines.Add("$key=$protected") }
}

if ($Name) {
    $secure = Read-Host -AsSecureString "Value for $Name"
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    Set-Value $Name (Protect $plain)
    Write-Host "Encrypted $Name"
} else {
    foreach ($key in $secretKeys) {
        $line = $lines | Where-Object { $_ -match "^\s*$key=(.+)$" } | Select-Object -Last 1
        if (-not $line) { continue }
        $value = ($line -split '=', 2)[1].Trim()
        if ($value -eq '' -or $value.StartsWith('dpapi')) { continue }
        Set-Value $key (Protect $value)
        Write-Host "Encrypted $key"
    }
}

[IO.File]::WriteAllLines((Resolve-Path $EnvFile), $lines)
Write-Host "Done. Restart the portal to use the protected values."
