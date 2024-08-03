function Update-ESC4Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC4 issues.

    .DESCRIPTION
        This function takes a single ESC4 issue as input. It then prompts the user if the principal with the ESC4 rights
        administers the template in question.
        If the principal is an admin of the template, the Issue attribute to indicate this configuration is expected, and
        the Fix attribute for the issue is updated to indicate no remediation is needed.
        If the the principal is not an admin of the template AND the rights assigned is GenericAll, Locksmith will ask
        if Enroll or AutoEnroll rights are needed.
        Depending on the answers to the listed questions, the Fix attribute is updated accordingly.

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC4 issue.

    .OUTPUTS
        This function updates ESC4 remediations customized to the user's needs.

    .EXAMPLE
        $Target = Get-Target
        $ADCSObjects = Get-ADCSObject -Target $Target
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $ESC4Issues = Find-ESC4 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes
        foreach ($issue in $ESCIssues) { Update-ESC4Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        $Issue
    )

    $Header = "`n[!] ESC4 Issue detected in $($Issue.Name)"
    Write-Host $Header -ForegroundColor Yellow
    Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
    Write-Host "$($Issue.IdentityReference) has $($Issue.ActiveDirectoryRights) rights on this template.`n"
    Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

    $Admin = ''
    do {
        $Admin = Read-Host "`nDoes $($Issue.IdentityReference) administer and/or maintain the $($Issue.Name) template? [y/n]"
    } while ( ($Admin -ne 'y') -and ($Admin -ne 'n') )

    if ($Admin -eq 'y') {
        $Issue.Issue = "$($Issue.IdentityReference) has $($Issue.ActiveDirectoryRights) rights on this template, but this is expected."
        $Issue.Fix = "No immediate remediation required."
    } elseif ($Issue.Issue -match 'GenericAll') {
        $RightsToRestore = 0
        while ($RightsToRestore -notin 1..5) {
            [string]$Question = @"

Does $($Issue.IdentityReference) need to Enroll and/or AutoEnroll in the $($Issue.Name) template?

  1. Enroll
  2. AutoEnroll
  3. Both
  4. Neither
  5. Unsure

Enter your selection [1-5]
"@
            $RightsToRestore = Read-Host $Question
        }

        switch ($RightsToRestore) {
            1 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$NewRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$EnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$NewRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
            2 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$AutoEnrollGuid = [System.Guid]::New('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$AutoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$AutoEnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$AutoEnrollRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
            3 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$AutoEnrollGuid = [System.Guid]::New('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$EnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$EnrollGuid, `$InheritanceType
`$AutoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$AutoEnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$EnrollRule)
`$ACL.AddAccessRule(`$AutoEnrollRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
            4 { break }
            5 {
                $Issue.Fix = @"
`$Path = 'AD:$($Issue.DistinguishedName)'
`$ACL = Get-Acl -Path `$Path
`$IdentityReference = [System.Security.Principal.NTAccount]::New('$($Issue.IdentityReference)')
`$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$AutoEnrollGuid = [System.Guid]::New('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$EnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$EnrollGuid, `$InheritanceType
`$AutoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$IdentityReference, `$ExtendedRight, `$AccessType, `$AutoEnrollGuid, `$InheritanceType
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
`$ACL.AddAccessRule(`$EnrollRule)
`$ACL.AddAccessRule(`$AutoEnrollRule)
Set-Acl -Path `$Path -AclObject `$ACL
"@
            }
        }
    }
}
