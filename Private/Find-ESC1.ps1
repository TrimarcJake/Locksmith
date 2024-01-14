function Find-ESC1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
        ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue = "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"
                    Fix = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique = 'ESC1'
                }
                $Issue
            }
        }
    }
}
