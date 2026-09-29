<#
.SYNOPSIS
    Creates an HTTPS certificate for the portal and writes TLS_PFX_PATH / TLS_PFX_PASSPHRASE to .env.

.DESCRIPTION
    -Mode Dev (default): self-signed certificate for localhost + this computer's names.
        Browsers will warn until you trust it (see README section 7.2).
    -Mode Ca: requests a certificate from your enterprise CA (AD CS, "WebServer" template) for -DnsName.
        The requesting account needs Enroll permission on the template; the CA may require approval.

    The PFX private key is protected with a random passphrase, which is stored DPAPI-encrypted in .env.

.EXAMPLE
    .\scripts\create-tls-cert.ps1
    .\scripts\create-tls-cert.ps1 -Mode Ca -DnsName password.corp.example -CAConfig "CA01.corp.example\Corp-Root-CA"
#>
param(
    [ValidateSet('Dev', 'Ca')] [string]$Mode = 'Dev',
    [string[]]$DnsName,
    [string]$CAConfig,
    [string]$Template = 'WebServer',
    [switch]$Machine
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$certDir = Join-Path $root 'certs'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$pfxPath = Join-Path $certDir 'portal-tls.pfx'

$fqdn = [Net.Dns]::GetHostEntry('').HostName
if (-not $DnsName) { $DnsName = @('localhost', $env:COMPUTERNAME, $fqdn) | Select-Object -Unique }

$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$passphrase = [Convert]::ToBase64String($bytes)
$securePass = ConvertTo-SecureString $passphrase -AsPlainText -Force

if ($Mode -eq 'Dev') {
    $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2) `
        -KeyExportPolicy Exportable -FriendlyName 'AD SSPR portal (dev)' -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
} else {
    $inf = Join-Path $env:TEMP 'sspr-cert.inf'
    $req = Join-Path $env:TEMP 'sspr-cert.req'
    $cer = Join-Path $env:TEMP 'sspr-cert.cer'
    $san = ($DnsName | ForEach-Object { "_continue_ = `"dns=$_&`"" }) -join "`r`n"
    @"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=$($DnsName[0])"
KeyLength = 2048
KeySpec = 1
Exportable = TRUE
MachineKeySet = FALSE
HashAlgorithm = SHA256
RequestType = PKCS10
[Extensions]
2.5.29.17 = "{text}"
$san
[RequestAttributes]
CertificateTemplate = $Template
"@ | Set-Content -Path $inf -Encoding ASCII
    Remove-Item $req, $cer -ErrorAction SilentlyContinue
    & certreq.exe -new -q $inf $req | Out-Null
    $submitArgs = @('-submit', '-q')
    if ($CAConfig) { $submitArgs += @('-config', $CAConfig) }
    & certreq.exe @submitArgs $req $cer
    if (-not (Test-Path $cer)) { throw 'Certificate was not issued (pending approval or no Enroll permission). Check the CA console.' }
    & certreq.exe -accept -user -q $cer | Out-Null
    $thumb = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $cer).Thumbprint
    $cert = Get-Item "Cert:\CurrentUser\My\$thumb"
    Remove-Item $inf, $req, $cer -ErrorAction SilentlyContinue
}

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePass | Out-Null
Write-Host "Saved $pfxPath"
Write-Host "  Subject:    $($cert.Subject)"
Write-Host "  Names:      $($DnsName -join ', ')"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Expires:    $($cert.NotAfter)"

# Store paths + encrypted passphrase in .env
$envFile = Join-Path $root '.env'
$lines = [Collections.Generic.List[string]](Get-Content $envFile)
if ($Machine) {
    Add-Type -AssemblyName System.Security
    $protected = 'dpapi-machine:' + [Convert]::ToBase64String(
        [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($passphrase), $null, 'LocalMachine'))
} else {
    $protected = 'dpapi:' + (ConvertFrom-SecureString $securePass)
}
foreach ($pair in @(@('TLS_PFX_PATH', 'certs/portal-tls.pfx'), @('TLS_PFX_PASSPHRASE', $protected))) {
    $found = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s*$($pair[0])=") { $lines[$i] = "$($pair[0])=$($pair[1])"; $found = $true }
    }
    if (-not $found) { $lines.Add("$($pair[0])=$($pair[1])") }
}
[IO.File]::WriteAllLines($envFile, $lines)
Write-Host 'Updated .env (TLS_PFX_PATH, TLS_PFX_PASSPHRASE encrypted). Restart the portal: https://<host>:<PORT>'
