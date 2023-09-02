param (
    [int]$Mode
)
function ConvertFrom-IdentityReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Object
    )

    $Principal = New-Object System.Security.Principal.NTAccount($Object)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    }
    else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    return $SID
}
function Export-RevertScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$AuditingIssues,
        [Parameter(Mandatory = $false)]
        [array]$ESC1,
        [Parameter(Mandatory = $false)]
        [array]$ESC2,
        [Parameter(Mandatory = $false)]
        [array]$ESC6
    )
    begin {
        $Output = 'Invoke-RevertLocksmith.ps1'
        Set-Content -Path $Output -Value "<#`nScript to revert changes performed by Locksmith`nCreated $(Get-Date)`n#>" -Force
        $Objects = $AuditingIssues + $ESC1 + $ESC2 + $ESC6
    }
    process {
        if ($Objects) {
            $Objects | ForEach-Object {
                Add-Content -Path $Output -Value $_.Revert
                Start-Sleep -Seconds 5
            }
        }
    }
}
function Find-AuditingIssue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKIEnrollmentService') -and
        ($_.AuditFilter -ne '127')
    } | ForEach-Object {
        $Issue = New-Object -TypeName pscustomobject
        $Issue | Add-Member -MemberType NoteProperty -Name 'Forest' -Value $_.CanonicalName.split('/')[0] -Force
        $Issue | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_.Name -Force
        $Issue | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $_.DistinguishedName -Force
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue | Add-Member -MemberType NoteProperty -Name 'Issue' -Value $_.AuditFilter -Force
            $Issue | Add-Member -MemberType NoteProperty -Name 'Fix' -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name 'Revert' -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name 'Technique' -Value 'DETECT' -Force
        }
        else {
            $Issue | Add-Member -MemberType NoteProperty -Name 'Issue' -Value "Auditing is not fully enabled. Current value is $($_.AuditFilter)" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name 'Fix' `
                -Value "certutil.exe -config `'$($_.CAFullname)`' -setreg `'CA\AuditFilter`' 127; Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name 'Revert' `
                -Value "certutil.exe -config $($_.CAFullname) -setreg CA\AuditFilter  $($_.AuditFilter); Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name 'Technique' -Value 'DETECT' -Force
        }
        $Severity = Set-Severity -Issue $Issue
        $Issue | Add-Member -MemberType NoteProperty -Name 'Severity' -Value $Severity
        $Issue
    }
}

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
        ($_.'msPKI-Enrollment-Flag' -ne 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC1'
                $Severity = Set-Severity -Issue $Issue
                $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
                $Issue
            }
        }
    }
}

function Find-ESC2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [string]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.ObjectClass -eq 'pKICertificateTemplate') -and
        ( (!$_.pkiExtendedKeyUsage) -or ($_.pkiExtendedKeyUsage -match '2.5.29.37.0') ) -and
        ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
        ($_.'msPKI-Enrollment-Flag' -ne 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) can request a SubCA certificate without Manager Approval" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC2'
                $Severity = Set-Severity -Issue $Issue
                $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
                $Issue
            }
        }
    }
}
function Find-ESC3Condition1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $EnrollmentAgentEKU) -and
        ($_.'msPKI-Enrollment-Flag' -ne 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) can enroll in this Enrollment Agent template without Manager Approval"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC3'
                $Severity = Set-Severity -Issue $Issue
                $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
                $Issue
            }
        }
    }
}
function Find-ESC3Condition2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKU) -and
        ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
        ($_.'msPKI-Enrollment-Flag' -ne 2) -and
        ($_.'msPKI-RA-Application-Policies' -eq '1.3.6.1.4.1.311.20.2.1') -and
        ( ($_.'msPKI-RA-Signature' -eq 1) )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC3'
                $Severity = Set-Severity -Issue $Issue
                $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
                $Issue
            }
        }
    }
}
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
        }
        else {
            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }
        if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
            $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                -Value "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value '[TODO]' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC4'
            $Severity = Set-Severity -Issue $Issue
            $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
            $Issue
        }
        if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -match $UnsafeOwners) ) {
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
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC4'
            $Severity = Set-Severity -Issue $Issue
            $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
            $Issue
        }
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($_.objectClass -eq 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) -and
                ($entry.ActiveDirectoryRights.ObjectType -notmatch $SafeObjectTypes)
            ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this template"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC4'
                $Severity = Set-Severity -Issue $Issue
                $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
                $Issue
            }
        }
    }
}
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
        }
        else {
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
            }
            else {
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
function Find-ESC6 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects
    )
    process {
        $ADCSObjects | Where-Object {
            ($_.objectClass -eq 'pKIEnrollmentService') -and
            ($_.SANFlag -ne 'No')
        } | ForEach-Object {
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            if ($_.SANFlag -eq 'Yes') {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "certutil -config $CAFullname -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "certutil -config $CAFullname -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            }
            else {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value $_.AuditFilter -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value 'N/A' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value 'N/A' -Force
            }
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC6'
            $Severity = Set-Severity -Issue $Issue
            $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
            $Issue
        }
    }
}
function Find-ESC8 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects
    )
    process {
        $ADCSObjects | Where-Object {
            $_.CAEnrollmentEndpoint
        } | ForEach-Object {
            $Issue = [ordered] @{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
            }
            if ($_.CAEnrollmentEndpoint -like '^http*') {
                $Issue['Issue'] = 'HTTP enrollment is enabled.'
                $Issue['CAEnrollmentEndpoint'] = $_.CAEnrollmentEndpoint
                $Issue['Fix'] = 'TBD - Remediate by doing 1, 2, and 3'
                $Issue['Revert'] = 'TBD'
            }
            else {
                $Issue['Issue'] = 'HTTPS enrollment is enabled.'
                $Issue['CAEnrollmentEndpoint'] = $_.CAEnrollmentEndpoint
                $Issue['Fix'] = 'TBD - Remediate by doing 1, 2, and 3'
                $Issue['Revert'] = 'TBD'
            }
            $Issue['Technique'] = 'ESC8'
            $Severity = Set-Severity -Issue $Issue
            $Issue['Severity'] = $Severity
            [PSCustomObject] $Issue
        }
    }
}
function Format-Result {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Issue,
        [Parameter(Mandatory = $true)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT = 'Auditing Not Fully Enabled'
        ESC1   = 'ESC1 - Vulnerable Certificate Template - Authentication'
        ESC2   = 'ESC2 - Vulnerable Certificate Template - Subordinate CA'
        ESC3   = 'ESC3 - Vulnerable Certificate Template - Enrollment Agent'
        ESC4   = 'ESC4 - Vulnerable Access Control - Certifcate Template'
        ESC5   = 'ESC5 - Vulnerable Access Control - PKI Object'
        ESC6   = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled'
        ESC8   = 'ESC8 - HTTP/S Enrollment Enabled'
    }

    if ($null -ne $Issue) {
        $UniqueIssue = $Issue.Technique | Sort-Object -Unique
        Write-Host "`n########## $($IssueTable[$UniqueIssue]) ##########`n"
        switch ($Mode) {
            0 {
                $Issue | Format-Table Technique, Name, Issue -Wrap
            }
            1 {
                if ($Issue.Technique -eq 'ESC8') {
                    $Issue | Format-List Technique, Name, DistinguishedName, CAEnrollmentEndpoint, Issue, Fix
                }
                else {
                    $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix
                    if (($Issue.Technique -eq "DETECT" -or $Issue.Technique -eq "ESC6") -and (Get-RestrictedAdminModeSetting)) {
                        Write-Warning "Restricted Admin Mode appears to be configured. Certutil.exe may not work from this host, therefore you may need to execute the 'Fix' commands on the CA server itself"
                    }
                }
            }
        }
    }
}
function Get-ADCSObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Targets,
        [System.Management.Automation.PSCredential]$Credential
    )
    foreach ( $forest in $Targets ) {
        if ($Credential) {
            $ADRoot = (Get-ADRootDSE -Credential $Credential -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties * -Credential $Credential
        }
        else {
            $ADRoot = (Get-ADRootDSE -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties *
        }
    }
}
function Get-CAHostObject {
    [CmdletBinding()]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [System.Management.Automation.PSCredential]$Credential
    )
    process {
        if ($Credential) {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC -Credential $Credential
            }
        }
        else {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC
            }
        }
    }
}
function Get-RestrictedAdminModeSetting {
    $Path = 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa'
    try {
        $RAM = (Get-ItemProperty -Path $Path).DisableRestrictedAdmin
        $Creds = (Get-ItemProperty -Path $Path).DisableRestrictedAdminOutboundCreds
        if ($RAM -eq '0' -and $Creds -eq '1') {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        return $false
    }
}
function Get-Target {
    param (
        [string]$Forest,
        [string]$InputPath,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Forest) {
        $Targets = $Forest
    }
    elseif ($InputPath) {
        $Targets = Get-Content $InputPath
    }
    else {
        if ($Credential) {
            $Targets = (Get-ADForest -Credential $Credential).Name
        }
        else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}
function New-OutputPath {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    # Create one output directory per forest
    foreach ( $forest in $Targets ) {
        $ForestPath = $OutputPath + "`\" + $forest
        New-Item -Path $ForestPath -ItemType Directory -Force  | Out-Null
    }
}
function Set-AdditionalCAProperty {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [System.Management.Automation.PSCredential]$Credential
    )
    process {
        $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
            [string]$CAEnrollmentEndpoint = $_.'msPKI-Enrollment-Servers' | Select-String 'http.*' | ForEach-Object { $_.Matches[0].Value }
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $CAHostname = $_.dNSHostName.split('.')[0]
            # $CAName = $_.Name
            if ($Credential) {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC -Credential $Credential).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC -Credential $Credential).DnsHostname
            }
            else {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC ).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC).DnsHostname
            }
            $ping = Test-Connection -ComputerName $CAHostFQDN -Quiet -Count 1
            if ($ping) {
                try {
                    if ($Credential) {
                        $CertutilAudit = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock { param($CAFullName); certutil -config $CAFullName -getreg CA\AuditFilter } -ArgumentList $CAFullName
                    }
                    else {
                        $CertutilAudit = certutil -config $CAFullName -getreg CA\AuditFilter
                    }
                }
                catch {
                    $AuditFilter = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilFlag = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock { param($CAFullName); certutil -config $CAFullName -getreg policy\EditFlags } -ArgumentList $CAFullName
                    }
                    else {
                        $CertutilFlag = certutil -config $CAFullName -getreg policy\EditFlags
                    }
                }
                catch {
                    $AuditFilter = 'Failure'
                }
            }
            else {
                $AuditFilter = 'CA Unavailable'
                $SANFlag = 'CA Unavailable'
            }
            if ($CertutilAudit) {
                try {
                    [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
                    $AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
                }
                catch {
                    try {
                        [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
                        $AuditFilter = $AuditFilter.split('=')[1].trim()
                    }
                    catch {
                        $AuditFilter = 'Never Configured'
                    }
                }
            }
            if ($CertutilFlag) {
                [string]$SANFlag = $CertutilFlag | Select-String ' EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 \('
                if ($SANFlag) {
                    $SANFlag = 'Yes'
                }
                else {
                    $SANFlag = 'No'
                }
            }
            Add-Member -InputObject $_ -MemberType NoteProperty -Name AuditFilter -Value $AuditFilter -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAEnrollmentEndpoint -Value $CAEnrollmentEndpoint -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAFullName -Value $CAFullName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostname -Value $CAHostname -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostDistinguishedName -Value $CAHostDistinguishedName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name SANFlag -Value $SANFlag -Force
        }
    }
}
function Set-Severity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Issue
    )
    foreach ($Finding in $Issue) {
        try {
            # Auditing
            if ($Finding.Technique -eq 'DETECT') {
                return 'Medium'
            }
            # ESC6
            if ($Finding.Technique -eq 'ESC6') {
                return 'High'
            }
            # ESC8
            if ($Finding.Technique -eq 'ESC8') {
                return 'High'
            }
            # ESC1, ESC2, ESC4, ESC5
            $SID = ConvertFrom-IdentityReference -Object $Finding.IdentityReference
            if ($SID -match $SafeUsers -or $SID -match $SafeOwners) {
                return 'Medium'
            }
            if (($SID -notmatch $SafeUsers -and $SID -notmatch $SafeOwners) -and ($Finding.ActiveDirectoryRights -match $DangerousRights)) {
                return 'Critical'
            }
        }
        catch {
            Write-Error "Could not determine issue severity for issue: $($Issue.Issue)"
            return 'Unknown Failure'
        }
    }
}

function Test-IsADAdmin {
    <#
    .SYNOPSIS
        Tests if the current user has administrative rights in Active Directory.
    .DESCRIPTION
        This function returns True if the current user is a Domain Admin (or equivalent) or False if not.
    .EXAMPLE
        Test-IsADAdmin
    .EXAMPLE
        if (!(Test-IsADAdmin)) { Write-Host "You are not running with Domain Admin rights and will not be able to make certain changes." -ForeGroundColor Yellow }
    #>
    if (
        # Need to test to make sure this checks domain groups and not local groups, particularly for 'Administrators' (reference SID instead of name?).
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Domain Admin") -or
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators") -or
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins")
    ) {
        Return $true
    }
    else {
        Return $false
    }
}

function Test-IsElevated {
    <#
    .SYNOPSIS
        Tests if PowerShell is running with elevated privileges (run as Administrator).
    .DESCRIPTION
        This function returns True if the script is being run as an administrator or False if not.
    .EXAMPLE
        Test-IsElevated
    .EXAMPLE
        if (!(Test-IsElevated)) { Write-Host "You are not running with elevated privileges and will not be able to make any changes." -ForeGroundColor Yellow }
    .EXAMPLE
        # Prompt to launch elevated if not already running as administrator:
        if (!(Test-IsElevated)) {
            $arguments = "& '" + $myinvocation.mycommand.definition + "'"
            Start-Process powershell -Verb runAs -ArgumentList $arguments
            Break
        }
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
function Test-IsLocalAccountSession {
    <#
    .SYNOPSIS
        Tests if the current session is running under a local user account or a domain account.
    .DESCRIPTION
        This function returns True if the current session is a local user or False if it is a domain user.
    .EXAMPLE
        Test-IsLocalAccountSession
    .EXAMPLE
        if ( (Test-IsLocalAccountSession) ) { Write-Host "You are running this script under a local account." -ForeGroundColor Yellow }
    #>
    [CmdletBinding()]

    $CurrentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $LocalSIDs = (Get-LocalUser).SID.Value
    if ($CurrentSID -in $LocalSIDs) {
        Return $true
    }
}

function Invoke-Locksmith {
    <#
    .SYNOPSIS
    Finds the most common malconfigurations of Active Directory Certificate Services (AD CS).

    .DESCRIPTION
    Locksmith uses the Active Directory (AD) Powershell (PS) module to identify 6 misconfigurations
    commonly found in Enterprise mode AD CS installations.

    .COMPONENT
    Locksmith requires the AD PS module to be installed in the scope of the Current User.
    If Locksmith does not identify the AD PS module as installed, it will attempt to
    install the module. If module installation does not complete successfully,
    Locksmith will fail.

    .PARAMETER Mode
    Specifies sets of common script execution modes.

    -Mode 0
    Finds any malconfigurations and displays them in the console.
    No attempt is made to fix identified issues.

    -Mode 1
    Finds any malconfigurations and displays them in the console.
    Displays example Powershell snippet that can be used to resolve the issue.
    No attempt is made to fix identified issues.

    -Mode 2
    Finds any malconfigurations and writes them to a series of CSV files.
    No attempt is made to fix identified issues.

    -Mode 3
    Finds any malconfigurations and writes them to a series of CSV files.
    Creates code snippets to fix each issue and writes them to an environment-specific custom .PS1 file.
    No attempt is made to fix identified issues.

    -Mode 4
    Finds any malconfigurations and creates code snippets to fix each issue.
    Attempts to fix all identified issues. This mode may require high-privileged access.

    .INPUTS
    None. You cannot pipe objects to Invoke-Locksmith.ps1.

    .OUTPUTS
    Output types:
    1. Console display of identified issues
    2. Console display of identified issues and their fixes
    3. CSV containing all identified issues
    4. CSV containing all identified issues and their fixes
    #>

    # Windows PowerShell cmdlet Restart-Service requires RunAsAdministrator

    [CmdletBinding()]
    param (
        [string]$Forest,
        [string]$InputPath,
        [int]$Mode = 0,
        [string]$OutputPath = (Get-Location).Path,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Check if ActiveDirectory PowerShell module is available, and attempt to install if not found
    if (-not(Get-Module -Name 'ActiveDirectory' -ListAvailable)) {
        if (Test-IsElevated) {
            $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
            # 1 - workstation, 2 - domain controller, 3 - non-dc server
            if ($OS -gt 1) {
                # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
                Install-WindowsFeature -Name RSAT-AD-PowerShell
            }
            else {
                # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
                Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
            }
        }
        else {
            Write-Warning -Message "The ActiveDirectory PowerShell module is required for Locksmith, but is not installed. Please launch an elevated PowerShell session to have this module installed for you automatically."
            # The goal here is to exit the script without closing the PowerShell window. Need to test.
            Return
        }
    }

    # Initial variables
    $Version = '2023.9'
    $AllDomainsCertPublishersSIDs = @()
    $AllDomainsDomainAdminSIDs = @()
    $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
    $DangerousRights = 'GenericAll|WriteDacl|WriteOwner|WriteProperty'
    $EnrollmentAgentEKU = '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'
    $ForestGC = $(Get-ADDomainController -Discover -Service GlobalCatalog -ForceDiscover | Select-Object -ExpandProperty Hostname) + ":3268"
    $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
    $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
    $UnsafeOwners = 'S-1-1-0|-11$|-513$|-515$'
    $UnsafeUsers = 'S-1-1-0|-11$|-513$|-515$'
    $Logo = @"
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'
                                                            v$Version

"@

    # Generated variables
    $DNSRoot = [string]((Get-ADForest).RootDomain | Get-ADDomain).DNSRoot
    $EnterpriseAdminsSID = ([string]((Get-ADForest).RootDomain | Get-ADDomain).DomainSID) + '-519'
    $PreferredOwner = New-Object System.Security.Principal.SecurityIdentifier($EnterpriseAdminsSID)
    $DomainSIDs = (Get-ADForest).Domains | ForEach-Object { (Get-ADDomain $_).DomainSID.Value }
    $DomainSIDs | ForEach-Object {
        $AllDomainsCertPublishersSIDs += $_ + '-517'
        $AllDomainsDomainAdminSIDs += $_ + '-512'
    }

    # Add SIDs of (probably) Safe Users to $SafeUsers
    Get-ADGroupMember $EnterpriseAdminsSID | ForEach-Object {
        $SafeUsers += '|' + $_.SID.Value
    }

    (Get-ADForest).Domains | ForEach-Object {
        $DomainSID = (Get-ADDomain $_).DomainSID.Value
        $SafeGroupRIDs = @('-517', '-512')
        $SafeGroupSIDs = @('S-1-5-32-544')
        foreach ($rid in $SafeGroupRIDs ) {
            $SafeGroupSIDs += $DomainSID + $rid
        }
        foreach ($sid in $SafeGroupSIDs) {
            $users += (Get-ADGroupMember $sid -Server $_ -Recursive).SID.Value
        }
        foreach ($user in $users) {
            $SafeUsers += '|' + $user
        }
    }

    if (!$Credential -and (Get-RestrictedAdminModeSetting)) {
        Write-Warning "Restricted Admin Mode appears to be in place, re-run with the '-Credential domain\user' option"
        break;
    }

    $Logo
    if ($Credential) {
        $Targets = Get-Target -Credential $Credential
    }
    else {
        $Targets = Get-Target
    }

    Write-Host "Gathering AD CS Objects from $($Targets)..."
    if ($Credential) {
        $ADCSObjects = Get-ADCSObject -Targets $Targets -Credential $Credential
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -Credential $Credential
        $ADCSObjects += Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential
        $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential
        $CAHosts | ForEach-Object { $SafeUsers += '|' + $_.Name }
    }
    else {
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects
        $ADCSObjects += Get-CAHostObject -ADCSObjects $ADCSObjects
        $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects
        $CAHosts | ForEach-Object { $SafeUsers += '|' + $_.Name }
    }

    Write-Host 'Identifying auditing issues...'
    [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects | Sort-Object Name

    Write-Host 'Identifying AD CS templates with dangerous configurations...'
    [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
    [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
    [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
    [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers

    Write-Host 'Identifying AD CS template and other objects with poor access control...'
    [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners | Sort-Object Name
    [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners | Sort-Object Name
    [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects | Sort-Object Name

    Write-Host 'Identifying HTTP-based certificate enrollment interfaces...'
    [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects | Sort-Object Name

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC8

    # If these are all empty = no issues found, exit
    if ((!$AuditingIssues) -and (!$ESC1) -and (!$ESC2) -and (!$ESC3) -and (!$ESC4) -and (!$ESC5) -and (!$ESC6) -and (!$ESC8) ) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
        break
    }

    switch ($Mode) {
        0 {
            Format-Result $AuditingIssues '0'
            Format-Result $ESC1 '0'
            Format-Result $ESC2 '0'
            Format-Result $ESC3 '0'
            Format-Result $ESC4 '0'
            Format-Result $ESC5 '0'
            Format-Result $ESC6 '0'
            Format-Result $ESC8 '0'
        }
        1 {
            Format-Result $AuditingIssues '1'
            Format-Result $ESC1 '1'
            Format-Result $ESC2 '1'
            Format-Result $ESC3 '1'
            Format-Result $ESC4 '1'
            Format-Result $ESC5 '1'
            Format-Result $ESC6 '1'
            Format-Result $ESC8 '1'
        }
        2 {
            $Output = 'ADCSIssues.CSV'
            Write-Host "Writing AD CS issues to $Output..."
            try {
                $AllIssues | Select-Object Forest, Technique, Name, Issue | Export-Csv -NoTypeInformation $Output
                Write-Host "$Output created successfully!"
            }
            catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        3 {
            $Output = 'ADCSRemediation.CSV'
            Write-Host "Writing AD CS issues to $Output..."
            try {
                $AllIssues | Select-Object Forest, Technique, Name, DistinguishedName, Issue, Fix | Export-Csv -NoTypeInformation $Output
                Write-Host "$Output created successfully!"
            }
            catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        4 {
            Write-Host 'Creating a script to revert any changes made by Locksmith...'
            try {
                Export-RevertScript -AuditingIssues $AuditingIssues -ESC1 $ESC1 -ESC2 $ESC2 -ESC6 $ESC6 
            }
            catch {
            }
            Write-Host 'Executing Mode 4 - Attempting to fix all identified issues!'
            if ($AuditingIssues) {
                $AuditingIssues | ForEach-Object {
                    $FixBlock = [scriptblock]::Create($_.Fix)
                    Write-Host "Attempting to fully enable AD CS auditing on $($_.Name)..."
                    Write-Host "This should have little impact on your environment.`n"
                    Write-Host 'Command(s) to be run:'
                    Write-Host 'PS> ' -NoNewline
                    Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                    try {
                        $WarningError = $null
                        Write-Warning 'If you continue, this script will attempt to fix this issue.' -WarningAction Inquire -ErrorVariable WarningError
                        if (!$WarningError) {
                            try {
                                Invoke-Command -ScriptBlock $FixBlock
                            }
                            catch {
                                Write-Error 'Could not modify AD CS auditing. Are you a local admin on this host?'
                            }
                        }
                    }
                    catch {
                        Write-Host 'SKIPPED!' -ForegroundColor Yellow
                    }
                    Read-Host -Prompt 'Press enter to continue...'
                }
            }
            if ($ESC1) {
                $ESC1 | ForEach-Object {
                    $FixBlock = [scriptblock]::Create($_.Fix)
                    Write-Host "Attempting to enable Manager Approval on the $($_.Name) template...`n"
                    Write-Host 'Command(s) to be run:'
                    Write-Host 'PS> ' -NoNewline
                    Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                    try {
                        $WarningError = $null
                        Write-Warning "This could cause some services to stop working until certificates are approved.`nIf you continue this script will attempt to fix this issues." -WarningAction Inquire -ErrorVariable WarningError
                        if (!$WarningError) {
                            try {
                                Invoke-Command -ScriptBlock $FixBlock
                            }
                            catch {
                                Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                            }
                        }
                    }
                    catch {
                        Write-Host 'SKIPPED!' -ForegroundColor Yellow
                    }
                    Read-Host -Prompt 'Press enter to continue...'
                }
            }
            if ($ESC2) {
                $ESC2 | ForEach-Object {
                    $FixBlock = [scriptblock]::Create($_.Fix)
                    Write-Host "Attempting to enable Manager Approval on the $($_.Name) template...`n"
                    Write-Host 'Command(s) to be run:'
                    Write-Host 'PS> ' -NoNewline
                    Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                    try {
                        $WarningError = $null
                        Write-Warning "This could cause some services to stop working until certificates are approved.`nIf you continue, this script will attempt to fix this issue." -WarningAction Inquire -ErrorVariable WarningError
                        if (!$WarningError) {
                            try {
                                Invoke-Command -ScriptBlock $FixBlock
                            }
                            catch {
                                Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                            }
                        }
                    }
                    catch {
                        Write-Host 'SKIPPED!' -ForegroundColor Yellow
                    }
                    Read-Host -Prompt 'Press enter to continue...'
                }
            }
            if ($ESC6) {
                $ESC6 | ForEach-Object {
                    $FixBlock = [scriptblock]::Create($_.Fix)
                    Write-Host "Attempting to disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on $($_.Name)...`n"
                    Write-Host 'Command(s) to be run:'
                    Write-Host 'PS> ' -NoNewline
                    Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                    try {
                        $WarningError = $null
                        Write-Warning "This could cause some services to stop working.`nIf you continue this script will attempt to fix this issues." -WarningAction Inquire -ErrorVariable WarningError
                        if (!$WarningError) {
                            try {
                                Invoke-Command -ScriptBlock $FixBlock
                            }
                            catch {
                                Write-Error 'Could not disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Are you an Active Directory or AD CS admin?'
                            }
                        }
                    }
                    catch {
                        Write-Host 'SKIPPED!' -ForegroundColor Yellow
                    }
                    Read-Host -Prompt 'Press enter to continue...'
                }
            }
        }
    }
}


Invoke-Locksmith -Mode $Mode
