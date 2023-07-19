function Find-ESC5 {
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
        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and 
            ($SID -notmatch $SafeOwners) -and
            ($entry.ActiveDirectoryRights.ObjectType -notmatch $SafeObjectTypes)            
            ) {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
            $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                -Value "$($_.nTSecurityDescriptor.Owner) has Owner rights on this object" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value '[TODO]' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC5'
            $Severity = Set-Severity -Issue $Issue
            $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
            $Issue
        }
        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -match $UnsafeOwners) ) {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
            $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                -Value "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC5'
            $Severity = Set-Severity -Issue $Issue
            $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
            $Issue
        }
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($_.objectClass -ne 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this object" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC5'
                $Severity = Set-Severity -Issue $Issue
                $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
                $Issue
            }
        }
    }
}