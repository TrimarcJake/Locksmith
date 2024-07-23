function Update-ESC4Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC4 issues.

    .DESCRIPTION


    .PARAMETER Issue


    .PARAMETER Mode


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
        Update-ESC4Remediation -ESC4Issues $ESC4Issues
    #>
    [CmdletBinding()]
    param(
        $Issue
    )

    Write-Host $Issue.Issue
    $Admin = ''
    while ( ($Admin -ne 'y') -and ($Admin -ne 'n') ) {
        $Admin = Read-Host "Does $($Issue.IdentityReference) administer and/or maintain this template? [y/n]"
    }

    if ($Admin -eq 'y') {
        $Issue.Issue = "$($Issue.IdentityReference) has $($Issue.ActiveDirectoryRights) rights on this template, but this is expected"
        $Issue.Fix = "No immediate remediation required."
    } else {
        if ($Issue.Issue -match 'GenericAll') {
            $RightsToRestore = 0
            while ($RightsToRestore -in 1..5) {
                [string]$Question = @"
Does $($Issue.IdentityReference) need to Enroll and/or AutoEnroll in this template? [1-5]"
`t1. Enroll
`t2. AutoEnroll
`t3. Both
`t4. Neither
`t5. Unsure
"@
                $RightsToRestore = Read-Host $Question
            }

            switch ($RightsToRestore) {
                1 {
                    $Issue.Fix = @"
`$Path = $($Issue.DistinguishedName)
`$ACL = Get-Acl -Path `$Path
`IdentityReference = [System.Principal.NTAccount]::New($($Issue.IdentityReference))
`$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
`$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
`$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
`$NewRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $accessType, $enrollGuid, $inheritanceType
foreach ( `$ace in `$ACL.access )
    if ( (`$ace.IdentityReference.Value -like '$($Issue.IdentityReference)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
$ACL.AddAccessRule(`$NewRule)
Set-Acl -Path `$Path -AclObject $ACL
"@
                }
                2 {

                }
                3 {

                }
                4 { break }
                5 {
                }
            }
        }
    }
}
