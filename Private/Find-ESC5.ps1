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
        Specifies a list of ObjectTypes that are not a security concern. This parameter is mandatory.

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
        # -521$    = Read-Only Domain Controllers
        # -9$      = Enterprise Domain Controllers
        # -526$    = Key Admins
        # -527$    = Enterprise Key Admins
        # S-1-5-10 = SELF
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'

        # The well-known GUIDs for Enroll and AutoEnroll rights on AD CS templates.
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $Results = $ADCSObjects | Find-ESC5 -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers  -SafeObjectTypes $SafeObjectTypes
        $Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$DangerousRights,
        [Parameter(Mandatory)]
        [string]$SafeOwners,
        [Parameter(Mandatory)]
        [string]$SafeUsers,
        [Parameter(Mandatory)]
        [string]$SafeObjectTypes,
        [Parameter(Mandatory)]
        [string]$UnsafeUsers,
        [switch]$SkipRisk
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

        $IssueDetail = ''
        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            switch ($_.objectClass) {
                container {
                    $IssueDetail = @"
With ownership rights, this principal can modify the container as they wish.
Depending on the exact container, this may result in the rights to create new
CA objects, new templates, new OIDs, etc. to create novel escalation paths.
"@
                }
                computer {
                    $IssueDetail = @"
This computer is hosting a Certification Authority (CA).

There is no reason for anyone other than AD Admins to have own CA host objects.
"@
                }
                'msPKI-Cert-Template-OID' {
                    $IssueDetail = @"
This Object Identifier (OID) can be modified into an Application Policy and linked
to an empty Universal Group.

If this principal also has ownership or control over a certificate template
(see ESC4), an attacker could link this Application Policy to the template. Once
linked, any certificates issued from that template would allow an attacker to
act as a member of the linked group (see ESC13).
"@
                }
                pKIEnrollmentService {
                    $IssueDetail = @"
Ownership rights can be used to enable currently disabled templates.

If this prinicpal also has control over a disabled certificate template (aka ESC4),
they could modify the template into an ESC1 template and enable the certificate.
This ensabled certificate could be use for privilege escalation and persistence.
"@
                }
            }
            if ($_.objectClass -eq 'certificationAuthority' -and $_.Name -eq 'NTAuthCertificates') {
                $IssueDetail = @"
The NTAuthCertificates object determines which Certification Authorities are
trusted by Active Directory (AD) for client authentication of all forms.

This principal can use their granted rights on NTAuthCertificates to add their own
rogue CAs. Once the rogue CA is trusted by AD, any client authentication
certificate generated by the CA can be used by the attacker to authenticate.
"@
            }

            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $_.nTSecurityDescriptor.Owner
                IdentityReferenceSID  = $SID
                ActiveDirectoryRights = 'Owner'
                objectClass           = $_.objectClass
                Issue                 = @"
$($_.nTSecurityDescriptor.Owner) has Owner rights on this $($_.objectClass) object. They are able
to modify this object in whatever way they wish.

$IssueDetail

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
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
            } # end switch ($_.objectClass)
            if ($SkipRisk -eq $false) {
                Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
            }
            $Issue
        } # end if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) )

        $IssueDetail = ''
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }

            switch ($_.objectClass) {
                container {
                    $IssueDetail = @"
With these rights, this principal may be able to modify the container as they wish.
Depending on the exact container, this may result in the rights to create new
CA objects, new templates, new OIDs, etc. to create novel escalation paths.
"@
                }
                computer {
                    $IssueDetail = @"
This computer is hosting a Certification Authority (CA). It is likely
$($entry.IdentityReference) can take control of this object.

There is little reason for anyone other than AD Admins to have elevated rights
to this CA host.
"@
                }
                'msPKI-Cert-Template-OID' {
                    $IssueDetail = @"
This Object Identifier (OID) can be modified into an Application Policy and linked
to an empty Universal Group.

If $($entry.IdentityReference) also has control over a certificate template
(see ESC4), an attacker could link this Application Policy to the template. Once
linked, any certificates issued from that template would allow an attacker to
act as a member of the linked group (see ESC13).
"@
                }
                pKIEnrollmentService {
                    $IssueDetail = @"
$($entry.IdentityReference) can use these elevated rights to publish currently
disabled templates.

If $($entry.IdentityReference) also has control over a disabled certificate
template (see ESC4), they could modify the template into an ESC1 template then
enable the certificate. This enabled certificate could be use for privilege
escalation and persistence.
"@
                }
            } # end switch ($_.objectClass)
            if ($_.objectClass -eq 'certificationAuthority' -and $_.Name -eq 'NTAuthCertificates') {
                $IssueDetail = @"
The NTAuthCertificates object determines which Certification Authorities are
trusted by Active Directory (AD) for client authentication of all forms.

$($entry.IdentityReference) can use their granted rights on NTAuthCertificates
to add their own rogue CAs. Once the rogue CA is trusted, any client authentication
certificates generated by the it can be used by the attacker.
"@
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
                    IdentityReferenceSID  = $SID
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    objectClass           = $_.objectClass
                    Issue                 = @"
$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) elevated rights
on this $($_.objectClass) object.

$IssueDetail

"@
                    Fix                   = @"
`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'
foreach ( `$ace in `$ACL.access ) {
    if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and
        ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        `$ACL.RemoveAccessRule(`$ace) | Out-Null
    }
}
Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL
"@
                    Revert                = '[TODO]'
                    Technique             = 'ESC5'
                }
                if ($SkipRisk -eq $false) {
                    Set-RiskRating -ADCSObjects $ADCSObjects -Issue $Issue -SafeUsers $SafeUsers -UnsafeUsers $UnsafeUsers
                }
                $Issue
            } # end if ( ($_.objectClass -ne 'pKICertificateTemplate')
        } # end foreach ($entry in $_.nTSecurityDescriptor.Access)
    } # end $ADCSObjects | ForEach-Object
}
