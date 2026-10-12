# Helper for windowsDirectoryService.js (AD2_MODE=windows). One operation per call against the second
# domain through ADSI with Kerberos/NTLM sign-and-seal on LDAP 389, so no certificate is needed.
# AD itself refuses unicodePwd writes on a connection that is not sealed or TLS-protected.
# Input and output: base64 of UTF-8 JSON on stdin/stdout (secrets never appear on the command line).
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices

function Write-Result($obj) {
    $json = ConvertTo-Json -InputObject $obj -Compress -Depth 4
    [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
}

try {
    $req = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())) | ConvertFrom-Json
    $auth = [DirectoryServices.AuthenticationTypes]'Secure, Signing, Sealing, ServerBind'

    # PowerShell adapts DirectoryEntry to its LDAP attributes; .NET members are reached through .psbase
    function Open-Entry([string]$dn) {
        New-Object DirectoryServices.DirectoryEntry("LDAP://$($req.server)/$dn", $req.bindUser, $req.bindPassword, $auth)
    }

    function Find-One([string]$filter, [string[]]$properties) {
        $base = $req.searchBase
        if (-not $base) { $base = [string](Open-Entry 'RootDSE').psbase.Properties['defaultNamingContext'].Value }
        $searcher = New-Object DirectoryServices.DirectorySearcher((Open-Entry $base), $filter, $properties)
        $searcher.SearchScope = [DirectoryServices.SearchScope]::Subtree
        $searcher.ReferralChasing = [DirectoryServices.ReferralChasingOption]::None
        $searcher.FindOne()
    }

    function First($result, [string]$name) {
        $values = $result.Properties[$name]
        if ($values.Count) { [string]$values[0] } else { $null }
    }

    switch ($req.op) {
        'findUser' {
            $r = Find-One "(&(objectClass=user)(objectCategory=person)(sAMAccountName=$($req.filterValue)))" @('distinguishedName', 'sAMAccountName', 'userAccountControl', 'adminCount')
            $user = $null
            if ($r) {
                $user = @{
                    dn = First $r 'distinguishedname'
                    sAMAccountName = First $r 'samaccountname'
                    userAccountControl = First $r 'useraccountcontrol'
                    adminCount = First $r 'admincount'
                }
            }
            Write-Result @{ ok = $true; user = $user }
        }
        'changePassword' {
            $entry = Open-Entry $req.dn
            # Bind now so connection/credential errors surface as such, not as a missing property
            # (a method call, because PowerShell swallows exceptions from property getters)
            $entry.psbase.RefreshCache([string[]]@('distinguishedName'))
            $entry.psbase.Properties['unicodePwd'].Value = [Text.Encoding]::Unicode.GetBytes('"' + $req.newPassword + '"')
            $entry.psbase.CommitChanges()
            Write-Result @{ ok = $true }
        }
        'isPrivileged' {
            $r = Find-One "(&(objectClass=user)(sAMAccountName=$($req.filterValue)))" @('adminCount')
            Write-Result @{ ok = $true; privileged = [bool]($r -and (First $r 'admincount') -eq '1') }
        }
        default { throw "Unknown operation '$($req.op)'" }
    }
} catch {
    $messages = @()
    $e = $_.Exception
    while ($e) {
        $messages += '{0} (0x{1:X8})' -f $e.Message.Trim(), $e.HResult
        if ($e -is [DirectoryServices.DirectoryServicesCOMException] -and $e.ExtendedErrorMessage) {
            $messages += $e.ExtendedErrorMessage.Trim()
        }
        $e = $e.InnerException
    }
    Write-Result @{ ok = $false; error = (($messages | Select-Object -Unique) -join ' | ') }
}
