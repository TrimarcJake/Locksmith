function Find-ESC4 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects,
        [Parameter(Mandatory = $true)]
        $DangerousRights,
        [Parameter(Mandatory = $true)]
        $SafeOwners,
        [Parameter(Mandatory = $true)]
        $SafeUsers
    )
    $ADCSObjects | ForEach-Object {
        $Principal = New-Object System.Security.Principal.NTAccount($_.nTSecurityDescriptor.Owner)
        if ($Principal -match '^(S-1|O:)') {
            $SID = $Principal
        } else {
            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }

        if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -match $UnsafeOwners) ) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $entry.IdentityReference
                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix                   = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Revert                = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Technique             = 'ESC4'
            }
            $Issue
        } elseif ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $entry.IdentityReference
                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix                   = '[TODO]'
                Revert                = '[TODO]'
                Technique             = 'ESC4'
            }
            $Issue
        }

        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($_.objectClass -eq 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) -and
                ($entry.ActiveDirectoryRights.ObjectType -notmatch $SafeObjectTypes)
                ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this template"
                    Fix                   = "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }"
                    Revert                = '[TODO]'
                    Technique             = 'ESC4'
                }
                $Issue
            }
        }
    }
}
