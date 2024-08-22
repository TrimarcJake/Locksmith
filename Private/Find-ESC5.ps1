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

    .PARAMETER SafeObjectTypes
        Specifices a list of ObjectTypes which are not a security concern. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject

        # GenericAll, WriteDacl, and WriteOwner all permit full control of an AD object.
        # WriteProperty may or may not permit full control depending the specific property and AD object type.
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')

        # -512$ = Domain Admins group
        # -519$ = Enterprise Admins group
        # -544$ = Administrators group
        # -18$  = SYSTEM
        # -517$ = Cert Publishers
        # -500$ = Built-in Administrator
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'

        # -512$    = Domain Admins group
        # -519$    = Enterprise Admins group
        # -544$    = Administrators group
        # -18$     = SYSTEM
        # -517$    = Cert Publishers
        # -500$    = Built-in Administrator
        # -516$    = Domain Controllers
        # -9$      = Enterprise Domain Controllers
        # -526$    = Key Admins
        # -527$    = Enterprise Key Admins
        # S-1-5-10 = SELF
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'

        # The well-known GUIDs for Enroll and AutoEnroll rights on AD CS templates.
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $Results = $ADCSObjects | Find-ESC5 -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers  -SafeObjectTypes $SafeObjectTypes
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
        $SafeUsers,
        [Parameter(Mandatory = $true)]
        $SafeObjectTypes
    )
    $ADCSObjects | ForEach-Object {
        if ($_.Name -ne '' -and $null -ne $_.Name) {
            $Principal = New-Object System.Security.Principal.NTAccount($_.nTSecurityDescriptor.Owner)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
        }

        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix                   = @"
`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`')
`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'
`$ACL.SetOwner(`$Owner)
Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL
"@
                Revert                = "
`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`')
`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'
`$ACL.SetOwner(`$Owner)
Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Technique             = 'ESC5'
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
            if ( ($_.objectClass -ne 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.AccessControlType -eq 'Allow') -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) -and
                ($entry.ObjectType -notmatch $SafeObjectTypes) ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this object"
                    Fix                   = @"
`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL
"@
                    Revert                = '[TODO]'
                    Technique             = 'ESC5'
                }
                $Issue
            }
        }
    }
}
