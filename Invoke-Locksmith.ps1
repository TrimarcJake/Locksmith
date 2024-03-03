param (
    [int]$Mode,
    [Parameter()]
    [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe')]
    [array]$Scans = 'All'
)
function ConvertFrom-IdentityReference {
    <#
    .SYNOPSIS
        Converts an identity reference to a security identifier (SID).

    .DESCRIPTION
        The ConvertFrom-IdentityReference function takes an identity reference as input and
        converts it to a security identifier (SID). It supports both SID strings and NTAccount objects.

    .PARAMETER Object
        Specifies the identity reference to be converted. This parameter is mandatory.

    .EXAMPLE
        $object = "S-1-5-21-3623811015-3361044348-30300820-1013"
        ConvertFrom-IdentityReference -Object $object
        # Returns "S-1-5-21-3623811015-3361044348-30300820-1013"

    .EXAMPLE
        $object = New-Object System.Security.Principal.NTAccount("DOMAIN\User")
        ConvertFrom-IdentityReference -Object $object
        # Returns "S-1-5-21-3623811015-3361044348-30300820-1013"
    #>
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
    <#
    .SYNOPSIS
        Creates a script that reverts the changes performed by Locksmith.

    .DESCRIPTION
        This script is used to revert changes performed by Locksmith.
        It takes in various arrays of objects representing auditing issues and ESC misconfirugrations.
        It creates a new script called 'Invoke-RevertLocksmith.ps1' and adds the necessary commands
        to revert the changes made by Locksmith.

    .PARAMETER AuditingIssues
        An array of auditing issues to be reverted.

    .PARAMETER ESC1
        An array of ESC1 changes to be reverted.

    .PARAMETER ESC2
        An array of ESC2 changes to be reverted.

    .PARAMETER ESC3
        An array of ESC3 changes to be reverted.

    .PARAMETER ESC4
        An array of ESC4 changes to be reverted.

    .PARAMETER ESC5
        An array of ESC5 changes to be reverted.

    .PARAMETER ESC6
        An array of ESC6 changes to be reverted.

    .EXAMPLE
        Export-RevertScript -AuditingIssues $auditingIssues -ESC1 $ESC1 -ESC2 $ESC2 -ESC3 $ESC3 -ESC4 $ESC4 -ESC5 $ESC5 -ESC6 $ESC6
        Reverts the changes performed by Locksmith using the specified arrays of objects.
    #>

    [CmdletBinding()]
    param(
        [array]$AuditingIssues,
        [array]$ESC1,
        [array]$ESC2,
        [array]$ESC3,
        [array]$ESC4,
        [array]$ESC5,
        [array]$ESC6
    )
    begin {
        $Output = 'Invoke-RevertLocksmith.ps1'
        Set-Content -Path $Output -Value "<#`nScript to revert changes performed by Locksmith`nCreated $(Get-Date)`n#>" -Force
        $Objects = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6
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
    <#
    .SYNOPSIS
        A function to find auditing issues on AD CS CAs.

    .DESCRIPTION
        This script takes an array of AD CS objects and filters them based on specific criteria to identify auditing issues.
        It checks if the object's objectClass is 'pKIEnrollmentService' and if the AuditFilter is not equal to '127'.
        For each matching object, it creates a custom object with information about the issue, fix, and revert actions.

    .PARAMETER ADCSObjects
        Specifies an array of ADCS objects to be checked for auditing issues.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        A custom object is created for each ADCS object that matches the criteria, containing the following properties:
        - Forest: The forest name of the object.
        - Name: The name of the object.
        - DistinguishedName: The distinguished name of the object.
        - Technique: The technique used to detect the issue (always 'DETECT').
        - Issue: The description of the auditing issue.
        - Fix: The command to fix the auditing issue.
        - Revert: The command to revert the auditing issue.

    .EXAMPLE
        $ADCSObjects = Get-ADObject -Filter * -SearchBase 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
        $AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
        $AuditingIssues
        This example retrieves ADCS objects from the specified search base and passes them to the Find-AuditingIssue function.
        It then returns the auditing issues for later use.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects
    )

    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKIEnrollmentService') -and
        ($_.AuditFilter -ne '127')
    } | ForEach-Object {
        $Issue = [pscustomobject]@{
            Forest            = $_.CanonicalName.split('/')[0]
            Name              = $_.Name
            DistinguishedName = $_.DistinguishedName
            Technique         = 'DETECT'
            Issue             = "Auditing is not fully enabled on $($_.CAFullName). Current value is $($_.AuditFilter)"
            Fix               = "certutil.exe -config `'$($_.CAFullname)`' -setreg `'CA\AuditFilter`' 127; Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
            Revert            = "certutil.exe -config $($_.CAFullname) -setreg CA\AuditFilter  $($_.AuditFilter); Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
        }
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue.Issue = $_.AuditFilter
            $Issue.Fix = 'N/A'
            $Issue.Revert = 'N/A'
        }
        $Issue
    }
}

function Find-ESC1 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC1 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC1 -SafeUsers $SafeUsers
        $Results
    #>
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
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC1'
                }
                $Issue
            }
        }
    }
}

function Find-ESC2 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC2 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC2 -SafeUsers $SafeUsers
        $Results
    #>
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
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
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
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can request a SubCA certificate without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC2'
                }
                $Issue
            }
        }
    }
}

function Find-ESC3Condition1 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that match the first condition required for ESC3 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC3Condition1 -SafeUsers $SafeUsers
        $Results
    #>
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
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
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
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can enroll in this Enrollment Agent template without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC3'
                }
                $Issue
            }
        }
    }
}

function Find-ESC3Condition2 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that match the second condition required for ESC3 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC3Condition2 -SafeUsers $SafeUsers
        $Results
    #>
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
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
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
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC3'
                }
                $Issue
            }
        }
    }
}

function Find-ESC4 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC4 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER DangerousRights
        Specifies the list of dangerous rights that should not be assigned to users. This parameter is mandatory.

    .PARAMETER SafeOwners
        Specifies the list of SIDs of safe owners who are allowed to have owner rights on the objects. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC4 -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers
        $Results
    #>
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
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Issue             = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix               = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Revert            = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Technique         = 'ESC4'
            }
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
                ($entry.AccessControlType -eq 'Allow') -and
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

function Find-ESC5 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC5 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on the specified conditions.
        For each matching object, it creates a custom object with properties representing various information about
        the object, such as Forest, Name, DistinguishedName, IdentityReference, ActiveDirectoryRights, Issue, Fix, Revert, and Technique.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .PARAMETER DangerousRights
        Specifies the list of dangerous rights that should not be assigned to users. This parameter is mandatory.

    .PARAMETER SafeOwners
        Specifies the list of SIDs of safe owners who are allowed to have owner rights on the objects. This parameter is mandatory.

    .PARAMETER SafeUsers
        Specifies the list of SIDs of safe users who are allowed to have specific rights on the objects. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $Results = $ADCSObjects | Find-ESC5 -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers
        $Results
    #>
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

        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Issue             = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix               = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Revert            = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Technique         = 'ESC5'
            }
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
                ($entry.AccessControlType -eq 'Allow') -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) -and
                ($entry.ActiveDirectoryRights.ObjectType -notmatch $SafeObjectTypes) ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this object"
                    Fix                   = "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }"
                    Revert                = '[TODO]'
                    Technique             = 'ESC5'
                }
                $Issue
            }
        }
    }
}

function Find-ESC6 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC6 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass 
        'pKIEnrollmentService' and the SANFlag set to 'Yes'. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique, 
        Issue, Fix, and Revert.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Results = $ADCSObjects | Find-ESC6
        $Results
    #>
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
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Technique         = 'ESC6'
                Issue             = $_.AuditFilter
                Fix               = 'N/A'
                Revert            = 'N/A'
            }
            if ($_.SANFlag -eq 'Yes') {
                $Issue.Issue = 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.'
                $Issue.Fix = "certutil -config $CAFullname -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
                $Issue.Revert = "certutil -config $CAFullname -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
            }
            $Issue
        }
    }
}

function Find-ESC8 {
    <#
    .SYNOPSIS
        Finds ADCS objects with enrollment endpoints and identifies the enrollment type.

    .DESCRIPTION
        This script takes an array of ADCS objects and filters them based on the presence of a CA enrollment endpoint.
        It then determines the enrollment type (HTTP or HTTPS) for each object and returns the results.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to process. This parameter is mandatory.

    .OUTPUTS
        An object representing the ADCS object with the following properties:
        - Forest: The forest name of the object.
        - Name: The name of the object.
        - DistinguishedName: The distinguished name of the object.
        - CAEnrollmentEndpoint: The CA enrollment endpoint of the object.
        - Issue: The identified issue with the enrollment type.
        - Fix: The recommended fix for the issue.
        - Revert: The recommended revert action for the issue.
        - Technique: The technique used to identify the issue.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Results = $ADCSObjects | Find-ESC8
        $Results
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects
    )

    process {
        $ADCSObjects | Where-Object {
            $_.CAEnrollmentEndpoint
        } | ForEach-Object {
            $Issue = [pscustomobject]@{
                Forest               = $_.CanonicalName.split('/')[0]
                Name                 = $_.Name
                DistinguishedName    = $_.DistinguishedName
                CAEnrollmentEndpoint = $_.CAEnrollmentEndpoint
                Issue                = 'HTTP enrollment is enabled.'
                Fix                  = '[TODO]'
                Revert               = '[TODO]'
                Technique            = 'ESC8'
            }
            if ($_.CAEnrollmentEndpoint -like '^https*') {
                $Issue.Issue = 'HTTPS enrollment is enabled.'
            }
            $Issue
        }
    }
}

<#
    This is a working POC. I need to test both checks and possibly blend pieces of them.
    Then I need to fold this function into the Locksmith workflow.
#>

function Find-ESC9 {
    <#
    .SYNOPSIS
        Checks for ESC9 (No Security Extension) Vulnerability

    .DESCRIPTION
        This function checks for certificate templates that contain the flag CT_CLAG_NO_SECURITY_EXTENSION (0x80000),
        which will likely make them vulnerable to ESC9. Another factor to check for ESC9 is the registry values on AD
        domain controllers that can help harden certificate based authentication for Kerberos and SChannel.

    .NOTES
        An ESC9 condition exists when:

        - the new msPKI-Enrollment-Flag value on a certificate contains the flag CT_FLAG_NO_SECURITY_EXTENSION (0x80000)
        - AND an insecure regstry value is set on domain controllers:

          - the StrongCertificateBindingEnforcement registry value for Kerberos is not set to 2 (the default is 1) on domain controllers
            at HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc
          - OR the CertificateMappingMethods registry value for SCHANNEL contains the UPN flag on domain controllers at
            HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel

        When the CT_FLAG_NO_SECURITY_EXTENSION (0x80000) flag is set on a certificate template, the new szOID_NTDS_CA_SECURITY_EXT
        security extension will not be embedded in issued certificates. This security extension was added by Microsoft's
        patch KB5014754 ("Certificate-based authentication changes on Windows domain controllers") on May 10, 2022.

        The patch applies to all servers that run Active Directory Certificate Services and Windows domain controllers that
        service certificate-based authentication.
        https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

        Based on research from
        https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7,
        https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16,
        and on a very long conversation with Bing Chat.

        Additional notes from Cortana -- Bing when I pressed her to  tell me whether both conditions were required for ESC9 or only one of them:
            A certificate template can still be vulnerable to ESC9 even if the msPKI-Enrollment-Flag does not include
            CT_FLAG_NO_SECURITY_EXTENSION. This is because the vulnerability primarily arises from the ability of a
            requester to specify the subjectAltName in a Certificate Signing Request (CSR). If a requester can specify
            the subjectAltName in a CSR, they can request a certificate as anyone, including a domain admin user.
            Therefore, if a certificate template allows requesters to specify a subjectAltName and
            StrongCertificateBindingEnforcement is not set to 2, it could potentially be vulnerable to ESC9. However,
            the presence of CT_FLAG_NO_SECURITY_EXTENSION in msPKI-Enrollment-Flag is a clear indicator of a template
            being vulnerable to ESC9.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects
    )

    # Import the required module
    Import-Module ActiveDirectory

    # Get the configuration naming context
    $configNC = (Get-ADRootDSE).configurationNamingContext

    # Define the path to the Certificate Templates container
    $path = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    # Get all certificate templates
    $templates = Get-ADObject -Filter * -SearchBase $path -Properties msPKI-Enrollment-Flag, msPKI-Certificate-Name-Flag

    foreach ($template in $templates) {
        # Check if msPKI-Enrollment-Flag contains the CT_FLAG_NO_SECURITY_EXTENSION (0x80000) flag
        if ($template.'msPKI-Enrollment-Flag' -band 0x80000) {
            # Check if msPKI-Certificate-Name-Flag contains the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME (0x2) flag
            if ($template.'msPKI-Certificate-Name-Flag' -band 0x2) {
                # Output the template name
                Write-Output "Template Name: $($template.Name), Vulnerable to ESC9"
            }
        }
    }

    # AND / OR / ALSO

    Import-Module ActiveDirectory

    $templates = Get-ADObject -Filter { ObjectClass -eq "pKICertificateTemplate" } -Properties *
    foreach ($template in $templates) {
        $name = $template.Name

        $subjectNameFlag = $template.'msPKI-Cert-Template-OID'
        $subjectType = $template.'msPKI-Certificate-Application-Policy'
        $enrollmentFlag = $template.'msPKI-Enrollment-Flag'
        $certificateNameFlag = $template.'msPKI-Certificate-Name-Flag'

        # Check if the template is vulnerable to ESC9
        if ($subjectNameFlag -eq "Supply in the request" -and
                ($subjectType -eq "User" -or $subjectType -eq "Computer") -and
            # 0x200 means a certificate needs to include a template name certificate extension
            # 0x220 instructs the client to perform autoenrollment for the specified template
                ($enrollmentFlag -eq 0x200 -or $enrollmentFlag -eq 0x220) -and
            # 0x2 instructs the client to supply subject information in the certificate request (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT).
            #   This means that any user who is allowed to enroll in a certificate with this setting can request a certificate as any
            #   user in the network, including a privileged user.
            # 0x3 instructs the client to supply both the subject and subject alternate name information in the certificate request
                ($certificateNameFlag -eq 0x2 -or $certificateNameFlag -eq 0x3)) {

            # Print the template name and the vulnerability
            Write-Output "$name is vulnerable to ESC9"
        }
        else {
            # Print the template name and the status
            Write-Output "$name is not vulnerable to ESC9"
        }
    }
}

function Format-Result {
    <#
    .SYNOPSIS
        Formats the result of an issue for display.

    .DESCRIPTION
        This script formats the result of an issue for display based on the specified mode.

    .PARAMETER Issue
        The issue object containing information about the detected issue.

    .PARAMETER Mode
        The mode to determine the formatting style. Valid values are 0 and 1.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 0
        Formats the issue result in table format.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 1
        Formats the issue result in list format.

    .NOTES
        Author: Spencer Alessi
    #>
    [CmdletBinding()]
    param(
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
    <#
    .SYNOPSIS
        Retrieves Active Directory Certificate Services (AD CS) objects.

    .DESCRIPTION
        This script retrieves AD CS objects from the specified forests.
        It can be used to gather information about Public Key Services in Active Directory.

    .PARAMETER Targets
        Specifies the forest(s) from which to retrieve AD CS objects.

    .PARAMETER Credential
        Specifies the credentials to use for authentication when retrieving ADCS objects.

    .EXAMPLE
        Get-ADCSObject -Targets forest1.lan -Credential $cred
        This example retrieves ADCS objects from forest1.lan using the specified credentials.

    #>

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
    <#
    .SYNOPSIS
        Retrieves Certificate Authority (CA) host object(s) from Active Directory.

    .DESCRIPTION
        This script retrieves CA host object(s) associated with every CA configured in the target Active Directory forest.
        If a Credential is provided, the script retrieves the CA host object(s) using the specified credentials.
        If no Credential is provided, the script retrieves the CA host object(s) using the current credentials.

    .PARAMETER ADCSObjects
        Specifies an array of AD CS objects to retrieve the CA host object for.

    .PARAMETER Credential
        Specifies the credentials to use for retrieving the CA host object(s). If not provided, current credentials will be used.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Credential = Get-Credential
        Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential
    
        This example retrieves the CA host object(s) associated with every CA in the target forest using the provided credentials.

    .INPUTS
        System.Array

    .OUTPUTS
        System.Object

    #>
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
    <#
    .SYNOPSIS
        Retrieves the current configuration of the Restricted Admin Mode setting.

    .DESCRIPTION
        This script retrieves the current configuration of the Restricted Admin Mode setting from the registry. 
        It checks if the DisableRestrictedAdmin value is set to '0' and the DisableRestrictedAdminOutboundCreds value is set to '1'.
        If both conditions are met, it returns $true; otherwise, it returns $false.

    .PARAMETER None

    .EXAMPLE
        Get-RestrictedAdminModeSetting
        True
    #>

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
    <#
    .SYNOPSIS
        Retrieves the target forest(s) based on a provided forest name, input file, or current Active Directory forest.

    .DESCRIPTION
        This script retrieves the target forest(s) based on the provided forest name, input file, or current Active Directory forest.
        If the $Forest parameter is specified, the script sets the target to the provided forest.
        If the $InputPath parameter is specified, the script reads the target forest(s) from the file specified by the input path.
        If neither $Forest nor $InputPath is specified, the script retrieves objects from the current Active Directory forest.
        If the $Credential parameter is specified, the script retrieves the target(s) using the provided credentials.

    .PARAMETER Forest
        Specifies a single forest to retrieve objects from.

    .PARAMETER InputPath
        Specifies the path to the file containing the target forest(s).

    .PARAMETER Credential
        Specifies the credentials to use for retrieving the target(s) from the Active Directory forest.

    .EXAMPLE
        Get-Target -Forest "example.com"
        Sets the target forest to "example.com".

    .EXAMPLE
        Get-Target -InputPath "C:\targets.txt"
        Retrieves the target forest(s) from the file located at "C:\targets.txt".

    .EXAMPLE
        Get-Target -Credential $cred
        Sets the target forest to the current Active Directory forest using the provided credentials.

    .OUTPUTS
        System.String
        The target(s) retrieved based on the specified parameters.

    #>

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
function Install-RSATADPowerShell {
    <#
    .SYNOPSIS
        Installs the RSAT AD PowerShell module.
    .DESCRIPTION
        This function checks if the current process is elevated and if it is it will prompt to install the RSAT AD PowerShell module.
    .EXAMPLE
        Install-RSATADPowerShell
    #>
    if (Test-IsElevated) {
        $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        # 1 - workstation, 2 - domain controller, 3 - non-dc server
        if ($OS -gt 1) {
            Write-Warning "The Active Directory PowerShell module is not installed."
            Write-Host "If you continue, Locksmith will attempt to install the Active Directory PowerShell module for you.`n" -ForegroundColor Yellow
            Write-Host "`nCOMMAND: Install-WindowsFeature -Name RSAT-AD-PowerShell`n" -ForegroundColor Cyan
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
                    Install-WindowsFeature -Name RSAT-AD-PowerShell
                }
                catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            }
            else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        }
        else {
            Write-Warning "The Active Directory PowerShell module is not installed."
            Write-Host "If you continue, Locksmith will attempt to install the Active Directory PowerShell module for you.`n" -ForegroundColor Yellow
            Write-Host "`nCOMMAND: Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online`n" -ForegroundColor Cyan
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
                    Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
                }
                catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            }
            else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        }
    }
    else {
        Write-Warning -Message "The ActiveDirectory PowerShell module is required for Locksmith, but is not installed. Please launch an elevated PowerShell session to have this module installed for you automatically."
        # The goal here is to exit the script without closing the PowerShell window. Need to test.
        Return
    }
}
function Invoke-Remediation {
    <#
    .SYNOPSIS
    Runs any remediation scripts available.

    .DESCRIPTION
    This function offers to run any remediation code associated with identified issues.

    .PARAMETER AuditingIssues
    A PS Object containing all necessary information about auditing issues.

    .PARAMETER ESC1
    A PS Object containing all necessary information about ESC1 issues.

    .PARAMETER ESC2
    A PS Object containing all necessary information about ESC2 issues.

    .PARAMETER ESC3
    A PS Object containing all necessary information about ESC3 issues.

    .PARAMETER ESC4
    A PS Object containing all necessary information about ESC4 issues.

    .PARAMETER ESC5
    A PS Object containing all necessary information about ESC5 issues.

    .PARAMETER ESC6
    A PS Object containing all necessary information about ESC6 issues.

    .INPUTS
    PS Objects

    .OUTPUTS
    Console output
    #>

    [CmdletBinding()]
    param (
        $AuditingIssues,
        $ESC1,
        $ESC2,
        $ESC3,
        $ESC4,
        $ESC5,
        $ESC6
    )

    Write-Host "`nExecuting Mode 4 - Attempting to fix identified issues!`n" -ForegroundColor Green
    Write-Host 'Creating a script (' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1' -ForegroundColor White -NoNewline
    Write-Host ") which can be used to revert all changes made by Locksmith...`n"
    try {
        Export-RevertScript -AuditingIssues $AuditingIssues -ESC1 $ESC1 -ESC2 $ESC2 -ESC3 $ESC3 -ESC4 $ESC4 -ESC5 $ESC5 -ESC6 $ESC6
    }
    catch {
        Write-Warning 'Creation of Invoke-RevertLocksmith.ps1 failed.'
        Write-Host "Continue with this operation? [Y] Yes " -NoNewline
        Write-Host "[N] " -ForegroundColor Yellow -NoNewline
        Write-Host "No: " -NoNewline
        $WarningError = ''
        $WarningError = Read-Host
        if ($WarningError -like 'y') {
            # Continue
        }
        else {
            break
        }
    }
    if ($AuditingIssues) {
        $AuditingIssues | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "Auditing is not fully enabled on Certification Authority `"$($_.Name)`".`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to fully enable auditing on Certification Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not modify AD CS auditing. Are you a local admin on the CA host?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC1) {
        $ESC1 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "Security Principals can enroll in `"$($_.Name)`" template using a Subject Alternative Name without Manager Approval.`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'CCOMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC2) {
        $ESC2 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "Security Principals can enroll in `"$($_.Name)`" template and create a Subordinate Certification Authority without Manager Approval.`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC4) {
        $ESC4 | Where-Object Issue -Like "* Owner rights *" | ForEach-Object { # This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" template to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC5) {
        $ESC5 | Where-Object Issue -Like "* Owner rights *" | ForEach-Object { # This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" object to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC6) {
        $ESC6 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "The Certification Authority `"$($_.Name)`" has the dangerous EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on Certifiction Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            $WarningError = 'n'
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "Mode 4 Complete! There are no more issues that Locksmith can automatically resolve.`n" -ForegroundColor Green
    Write-Host 'If you experience any operational impact from using Locksmith Mode 4, use ' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1 ' -ForegroundColor White
    Write-Host "to revert all changes made by Locksmith. It can be found in the current working directory.`n"
    Write-Host @"
REMINDER: Locksmith cannot automatically resolve all AD CS issues at this time.
There may be more AD CS issues remaining in your environment.
Use Locksmith in Modes 0-3 to further investigate your environment
or reach out to the Locksmith team for assistance. We'd love to help!`n
"@ -ForegroundColor Yellow
}

function Invoke-Scans {
    <#
    .SYNOPSIS
        Invoke-Scans.ps1 is a script that performs various scans on ADCS (Active Directory Certificate Services) objects.

    .DESCRIPTION
        This script accepts a parameter named $Scans, which specifies the type of scans to perform. The available scan options are:
        - Auditing
        - ESC1
        - ESC2
        - ESC3
        - ESC4
        - ESC5
        - ESC6
        - ESC8
        - All
        - PromptMe

    .PARAMETER Scans
        Specifies the type of scans to perform. Multiple scan options can be provided as an array. The default value is 'All'.
        The available scan options are: 'Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe'.

    .NOTES
        - The script requires the following functions to be defined: Find-AuditingIssue, Find-ESC1, Find-ESC2, Find-ESC3Condition1,
          Find-ESC3Condition2, Find-ESC4, Find-ESC5, Find-ESC6, Find-ESC8.
        - The script uses Out-GridView or Out-ConsoleGridView for interactive selection when the 'PromptMe' scan option is chosen.
        - The script returns a hash table containing the results of the scans.

    .EXAMPLE
        # Perform all scans
        Invoke-Scans

    .EXAMPLE
        # Perform only the 'Auditing' and 'ESC1' scans
        Invoke-Scans -Scans 'Auditing', 'ESC1'

    .EXAMPLE
        # Prompt the user to select the scans to perform
        Invoke-Scans -Scans 'PromptMe'
    #>

    [CmdletBinding()]
    param (
        # Could split Scans and PromptMe into separate parameter sets.
        [Parameter()]
        [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe')]
        [array]$Scans = 'All'
    )

    # Is this needed?
    if ($Scans -eq $IsNullOrEmpty) {
        $Scans = 'All'
    }

    if ( $Scans -eq 'PromptMe' ) {
        $GridViewTitle = 'Select the tests to run and press Enter or click OK to continue...'

        # Check for Out-GridView or Out-ConsoleGridView
        if ((Get-Command Out-ConsoleGridView -ErrorAction SilentlyContinue) -and ($PSVersionTable.PSVersion.Major -ge 7)) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-ConsoleGridView -OutputMode Multiple -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        else {
            # To Do: Check for admin and prompt to install features/modules or revert to 'All'.
            Write-Information "Out-GridView and Out-ConsoleGridView were not found on your system. Defaulting to `'All`'."
            $Scans = 'All'
        }
    }

    switch ( $Scans ) {
        Auditing {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
        }
        ESC1 {
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC2 {
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC3 {
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC4 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
        }
        ESC5 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
        }
        ESC6 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
        }
        ESC8 {
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
        All {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
            Write-Host 'Identifying Certificate Authorities configured with dangerous flags (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
    }

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC8

    # If these are all empty = no issues found, exit
    if ((!$AuditingIssues) -and (!$ESC1) -and (!$ESC2) -and (!$ESC3) -and (!$ESC4) -and (!$ESC5) -and (!$ESC6) -and (!$ESC8) ) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
        break
    }

    # Return a hash table of array names (keys) and arrays (values) so they can be directly referenced with other functions
    Return @{
        AllIssues      = $AllIssues
        AuditingIssues = $AuditingIssues
        ESC1           = $ESC1
        ESC2           = $ESC2
        ESC3           = $ESC3
        ESC4           = $ESC4
        ESC5           = $ESC5
        ESC6           = $ESC6
        ESC8           = $ESC8
    }
}

<#
.SYNOPSIS
Create a dictionary of the escalation paths and insecure configurations that Locksmith scans for.

.DESCRIPTION
The New-Dictionary function is used to instantiate an array of objects that contain the names, definitions,
descriptions, code used to find, code used to fix, and reference URLs. This is invoked by the module's main function.

.NOTES

    VulnerableConfigurationItem Class Definition:
        Version         Update each time the class definition or the dictionary below is changed.
        Name            The short name of the vulnerable configuration item (VCI).
        Category        The high level category of VCI types, including escalation path, server configuration, GPO setting, etc.
        Subcategory     The subcategory of vulnerable configuration item types.
        Summary         A summary of the vulnerability and how it can be abused.
        FindIt          The name of the function that is used to look for the VCI, stored as an invokable scriptblock.
        FixIt           The name of the function that is used to fix the VCI, stored as an invokable scriptblock.
        ReferenceUrls   An array of URLs that are used as references to learn more about the VCI.
#>

function New-Dictionary {
    class VulnerableConfigurationItem {
        static [string] $Version = '2023.10.01.000'
        [string]$Name
        [ValidateSet('Escalation Path', 'Server Configuration', 'GPO Setting')][string]$Category
        [string]$Subcategory
        [string]$Summary
        [scriptblock]$FindIt
        [scriptblock]$FixIt
        [uri[]]$ReferenceUrls
    }

    [VulnerableConfigurationItem[]]$Dictionary = @(
        [VulnerableConfigurationItem]@{
            Name          = 'ESC1'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Client Authentication Templates'
            Summary       = ''
            FindIt        = { Find-ESC1 }
            FixIt         = { Write-Output "Add code to fix the vulnerable configuration." }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC1'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC2'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable SubCA/Any Purpose Templates'
            Summary       = ''
            FindIt        = { Find-ESC2 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC2'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC3'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Enrollment Agent Templates'
            Summary       = ''
            FindIt        = {
                Find-ESC3Condition1
                Find-ESC3Condition2
            }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Enrollment%20Agent%20Templates%20%E2%80%94%20ESC3'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC4';
            Category      = 'Escalation Path'
            Subcategory   = 'Certificate Templates with Vulnerable Access Controls'
            Summary       = ''
            FindIt        = { Find-ESC4 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Template%20Access%20Control%20%E2%80%94%20ESC4'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC5';
            Category      = 'Escalation Path'
            Subcategory   = 'PKI Objects with Vulnerable Access Control'
            Summary       = ''
            FindIt        = { Find-ESC5 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20PKI%20Object%20Access%20Control%20%E2%80%94%20ESC5'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC6'
            Category      = 'Escalation Path'
            Subcategory   = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
            Summary       = ''
            FindIt        = { Find-ESC6 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=EDITF_ATTRIBUTESUBJECTALTNAME2%20%E2%80%94%20ESC6'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC7'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Certificate Authority Access Control'
            Summary       = ''
            FindIt        = { Write-Output 'We have not created Find-ESC7 yet.' }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Authority%20Access%20Control%20%E2%80%94%20ESC7'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC8'
            Category      = 'Escalation Path'
            Subcategory   = 'AD CS HTTP Endpoints Vulnerable to NTLM Relay'
            Summary       = ''
            FindIt        = { Find-ESC8 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=NTLM%20Relay%20to%20AD%20CS%20HTTP%20Endpoints'
        },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC9'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC9}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC10'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC10}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC11'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC11}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        [VulnerableConfigurationItem]@{
            Name          = 'Auditing'
            Category      = 'Server Configuration'
            Subcategory   = 'Gaps in auditing on certificate authorities and AD CS objects.'
            Summary       = ''
            FindIt        = { Find-AuditingIssue }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = @('https://github.com/TrimarcJake/Locksmith', 'https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/designing-and-implementing-a-pki-part-i-design-and-planning/ba-p/396953')
        }
    )
    Return $Dictionary
}

function New-OutputPath {
    <#
    .SYNOPSIS
        Creates output directories for each forest.

    .DESCRIPTION
        This script creates one output directory per forest specified in the $Targets variable.
        The output directories are created under the $OutputPath directory.

    .PARAMETER Targets
        Specifies the forests for which output directories need to be created.

    .PARAMETER OutputPath
        Specifies the base path where the output directories will be created.

    .EXAMPLE
        New-OutputPath -Targets "Forest1", "Forest2" -OutputPath "C:\Output"
        This example creates two output directories named "Forest1" and "Forest2" under the "C:\Output" directory.

    #>

    [CmdletBinding(SupportsShouldProcess)]
    param ()
    # Create one output directory per forest
    foreach ( $forest in $Targets ) {
        $ForestPath = $OutputPath + "`\" + $forest
        New-Item -Path $ForestPath -ItemType Directory -Force  | Out-Null
    }
}

function Set-AdditionalCAProperty {
    <#
    .SYNOPSIS
        Sets additional properties for a Certificate Authority (CA) object.

    .DESCRIPTION
        This script sets additional properties for a Certificate Authority (CA) object.
        It takes an array of AD CS Objects as input, which represent the CA objects to be processed.
        The script filters the AD CS Objects based on the objectClass property and performs the necessary operations
        to set the additional properties.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS Objects to be processed. This parameter is mandatory and supports pipeline input.

    .PARAMETER Credential
        Specifies the PSCredential object to be used for authentication when accessing the CA objects.
        If not provided, the script will use the current user's credentials.

    .EXAMPLE
        $ADCSObjects = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' }
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects

    .NOTES
        Author: Jake Hildreth
        Date: July 15, 2022
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [PSCredential]$Credential
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

function Test-IsMemberOfProtectedUsers {
    <#
        .SYNOPSIS
            Check to see if a user is a member of the Protected Users group.

        .DESCRIPTION
            This function checks to see if a specified user or the current user is a member of the Protected Users group in AD.
            It also checked the user's primary group ID in case that is set to 525 (Protected Users).

        .PARAMETER User
            The user that will be checked for membership in the Protected Users group. This parameter accepts input from the pipeline.

        .EXAMPLE
            This example will check if JaneDoe is a member of the Protected Users group.

            Test-IsMemberOfProtectedUsers -User JaneDoe

        .EXAMPLE
            This example will check if the current user is a member of the Protected Users group.

            Test-IsMemberOfProtectedUsers

        .INPUTS
            Active Directory user object, user SID, SamAccountName, etc

        .OUTPUTS
            True, False
    #>

    [CmdletBinding()]
    param (
        # User parameter accepts any input that is valid for Get-ADUser
        [Parameter(
            ValueFromPipeline = $true
        )]
        $User
    )

    Import-Module ActiveDirectory

    # Use the currently logged in user if none is specified
    # Get the user from Active Directory
    if (-not($User)) {
        # These two are different types. Fixed by referencing $CheckUser.SID later, but should fix here by using one type.
        $CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[-1]
        $CheckUser = Get-ADUser $CurrentUser -Properties primaryGroupID
    }
    else {
        $CheckUser = Get-ADUser $User -Properties primaryGroupID
    }

    # Get the Protected Users group by SID instead of by its name to ensure compatibility with any locale or language.
    $DomainSID = (Get-ADDomain).DomainSID.Value
    $ProtectedUsersSID = "$DomainSID-525"

    # Get members of the Protected Users group for the current domain. Recuse in case groups are nested in it.
    $ProtectedUsers = Get-ADGroupMember -Identity $ProtectedUsersSID -Recursive | Select-Object -Unique

    # Check if the current user is in the 'Protected Users' group
    if ($ProtectedUsers.SID.Value -contains $CheckUser.SID) {
        Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is a member of the Protected Users group."
        $true
    }
    else {
        # Check if the user's PGID (primary group ID) is set to the Protected Users group RID (525).
        if ( $CheckUser.primaryGroupID -eq '525' ) {
            $true
        }
        else {
            Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is not a member of the Protected Users group."
            $false
        }
    }
}

function Test-IsRecentVersion {
    <#
    .SYNOPSIS
        Check if the installed version of the Locksmith module is up to date.

    .DESCRIPTION
        This script checks the installed version of the Locksmith module against the latest release on GitHub.
        It determines if the installed version is considered "out of date" based on the number of days specified.
        If the installed version is out of date, a warning message is displayed along with information about the latest release.

    .PARAMETER Version
        Specifies the version number to check from the script.

    .PARAMETER Days
        Specifies the number of days past a module release date at which to consider the release "out of date".
        The default value is 60 days.

    .OUTPUTS
        System.Boolean
        Returns $true if the installed version is up to date, and $false if it is out of date.

    .EXAMPLE
        Test-IsRecentVersion -Version "2024.1" -Days 30
        True

        Test-IsRecentVersion -Version "2023.10" -Days 60
        WARNING: Your currently installed version of Locksmith (2.5) is more than 60 days old. We recommend that you update to ensure the latest findings are included.
        Locksmith Module Details:
        Latest Version:          v2024.1
        Published at:            01/28/2024 12:47:18
        Install Module:     Install-Module -Name Locksmith
        Standalone Script:  https://github.com/trimarcjake/locksmith/releases/download/v2.6/Invoke-Locksmith.zip

    .NOTES
        Author: Sam Erde
        Date:   02/10/2024
    #>
    [CmdletBinding()]
    param (
        # Check a specific version number from the script
        [Parameter(Mandatory)]
        [string]$Version,
        # Define the number of days past a module release date at which to consider the release "out of date."
        [Parameter()]
        [int16]$Days = 60
    )

    # Strip the 'v' if it was used so the script can work with or without it in the input
    $Version = $Version.Replace('v', '')
    try {
        # Checking the most recent release in GitHub, but we could also use PowerShell Gallery.
        $Uri = "https://api.github.com/repos/trimarcjake/locksmith/releases"
        $Releases = Invoke-RestMethod -Uri $uri -Method Get -DisableKeepAlive -ErrorAction Stop
        $LatestRelease = $Releases | Sort-Object -Property Published_At -Descending | Select-Object -First 1
        # Get the release date of the currently running version via the version parameter
        [datetime]$InstalledVersionReleaseDate = ($Releases | Where-Object { $_.tag_name -like "?$Version" }).published_at
        [datetime]$LatestReleaseDate = $LatestRelease.published_at
        # $ModuleDownloadLink   = ( ($LatestRelease.Assets).Where({$_.Name -like "Locksmith-v*.zip"}) ).browser_download_url
        $ScriptDownloadLink = ( ($LatestRelease.Assets).Where({ $_.Name -eq 'Invoke-Locksmith.zip' }) ).browser_download_url

        $LatestReleaseInfo = @"
Locksmith Module Details:

Latest Version:`t`t $($LatestRelease.name)
Published at: `t`t $LatestReleaseDate
Install Module:`t`t Install-Module -Name Locksmith
Standalone Script:`t $ScriptDownloadLink
"@
    }
    catch {
        Write-Warning "Unable to find the latest available version of the Locksmith module on GitHub." -WarningAction Continue
        # Find the approximate release date of the installed version. Handles version with or without 'v' prefix.
        $InstalledVersionMonth = [datetime]::Parse(($Version.Replace('v', '')).Replace('.', '-') + "-01")
        # Release date is typically the first Saturday of the month. Let's guess as close as possible!
        $InstalledVersionReleaseDate = $InstalledVersionMonth.AddDays( 6 - ($InstallVersionMonth.DayOfWeek) )
    }

    # The date at which to consider this module "out of date" is based on the $Days parameter
    $OutOfDateDate = (Get-Date).Date.AddDays(-$Days)
    $OutOfDateMessage = "Your currently installed version of Locksmith ($Version) is more than $Days days old. We recommend that you update to ensure the latest findings are included."

    # Compare the installed version release date to the latest release date
    if ( ($LatestReleaseDate) -and ($InstalledVersionReleaseDate -le ($LatestReleaseDate.AddDays(-$Days))) ) {
        # If we found the latest release date online and the installed version is more than [x] days older than it:
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        Write-Information -MessageData $LatestReleaseInfo -InformationAction Continue
        $IsRecentVersion = $false
    }
    elseif ( $InstalledVersionReleaseDate -le $OutOfDateDate ) {
        # If we didn't get the latest release date online, use the estimated release date to check age.
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        $IsRecentVersion = $false
    }
    else {
        # The installed version has not been found to be out of date.
        $IsRecentVersion = $True
    }

    # Return true/false
    $IsRecentVersion
}

function Test-IsRSATInstalled {
    <#
    .SYNOPSIS
        Tests if the RSAT AD PowerShell module is installed.
    .DESCRIPTION
        This function returns True if the RSAT AD PowerShell module is installed or False if not.
    .EXAMPLE
        Test-IsElevated
    #>
    if (Get-Module -Name 'ActiveDirectory' -ListAvailable) {
        $true
    }
    else {
        $false
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

    .PARAMETER Scans
    Specify which scans you want to run. Available scans: 'All' or Auditing, ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC8, or 'PromptMe'

    -Scans All
    Run all scans (default)

    -Scans PromptMe
    Presents a grid view of the available scan types that can be selected and run them after you click OK.

    .PARAMETER OutputPath
    Specify the path where you want to save reports and mitigation scripts.

    .INPUTS
    None. You cannot pipe objects to Invoke-Locksmith.ps1.

    .OUTPUTS
    Output types:
    1. Console display of identified issues
    2. Console display of identified issues and their fixes
    3. CSV containing all identified issues
    4. CSV containing all identified issues and their fixes

    .NOTES
    Windows PowerShell cmdlet Restart-Service requires RunAsAdministrator
    #>

    [CmdletBinding()]
    param (
        [string]$Forest,
        [string]$InputPath,
        [int]$Mode = 0,
        [Parameter()]
        [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe')]
        [array]$Scans = 'All',
        [string]$OutputPath = (Get-Location).Path,
        [System.Management.Automation.PSCredential]$Credential
    )

    $Version = '2024.3'
    $LogoPart1 = @"
    _       _____  _______ _     _ _______ _______ _____ _______ _     _
    |      |     | |       |____/  |______ |  |  |   |      |    |_____|
    |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
"@
    $LogoPart2 = @"
        .--.                  .--.                  .--.
       /.-. '----------.     /.-. '----------.     /.-. '----------.
       \'-' .---'-''-'-'     \'-' .--'--''-'-'     \'-' .--'--'-''-'
        '--'                  '--'                  '--'
"@
    $VersionBanner = "                                                          v$Version"

    Write-Host $LogoPart1 -ForegroundColor Magenta
    Write-Host $LogoPart2 -ForegroundColor White
    Write-Host $VersionBanner -ForegroundColor Red

    # Check if ActiveDirectory PowerShell module is available, and attempt to install if not found
    $RSATInstalled = Test-IsRSATInstalled
    if ($RSATInstalled) {
        # Continue
    }
    else {
        Install-RSATADPowerShell
    }

    # Exit if running in restricted admin mode without explicit credentials
    if (!$Credential -and (Get-RestrictedAdminModeSetting)) {
        Write-Warning "Restricted Admin Mode appears to be in place, re-run with the '-Credential domain\user' option"
        break;
    }

    # Initial variables
    $AllDomainsCertPublishersSIDs = @()
    $AllDomainsDomainAdminSIDs = @()
    $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
    $DangerousRights = 'GenericAll|WriteDacl|WriteOwner|WriteProperty'
    $EnrollmentAgentEKU = '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'
    $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
    $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
    $UnsafeOwners = 'S-1-1-0|-11$|-513$|-515$'
    $UnsafeUsers = 'S-1-1-0|-11$|-513$|-515$'

    # Generated variables
    $Dictionary = New-Dictionary
    $ForestGC = $(Get-ADDomainController -Discover -Service GlobalCatalog -ForceDiscover | Select-Object -ExpandProperty Hostname) + ":3268"
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

    if ( $Scans ) {
        # If the Scans parameter was used, Invoke-Scans with the specified checks.
        $Results = Invoke-Scans -Scans $Scans
        # Re-hydrate the findings arrays from the Results hash table
        $AllIssues = $Results['AllIssues']
        $AuditingIssues = $Results['AuditingIssues']
        $ESC1 = $Results['ESC1']
        $ESC2 = $Results['ESC2']
        $ESC3 = $Results['ESC3']
        $ESC4 = $Results['ESC4']
        $ESC5 = $Results['ESC5']
        $ESC6 = $Results['ESC6']
        $ESC8 = $Results['ESC8']
    }

    # If these are all empty = no issues found, exit
    if ($null -eq $Results) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found.`n" -ForegroundColor Green
        Write-Host 'Thank you for using ' -NoNewline
        Write-Host "❤ Locksmith ❤ `n" -ForegroundColor Magenta
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
                Write-Host "$Output created successfully!`n"
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
                Write-Host "$Output created successfully!`n"
            }
            catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        4 {
            Invoke-Remediation -AuditingIssues $AuditingIssues -ESC1 $ESC1 -ESC2 $ESC2 -ESC3 $ESC3 -ESC4 $ESC4 -ESC5 $ESC5 -ESC6 $ESC6
        }
    }
    Write-Host 'Thank you for using ' -NoNewline
    Write-Host "❤ Locksmith ❤`n" -ForegroundColor Magenta
}


Invoke-Locksmith -Mode $Mode -Scans $Scans
