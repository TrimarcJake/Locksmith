﻿function Find-ESC2 {
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
        [Parameter(Mandatory)]
        [array]$ADCSObjects,
        [Parameter(Mandatory)]
        [string]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.ObjectClass -eq 'pKICertificateTemplate') -and
        ( (!$_.pkiExtendedKeyUsage) -or ($_.pkiExtendedKeyUsage -match '2.5.29.37.0') ) -and
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
            if ( ($SID -notmatch $SafeUsers) -and ( ($entry.ActiveDirectoryRights -match 'ExtendedRight') -or ($entry.ActiveDirectoryRights -match 'GenericAll') ) ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = @"
$($entry.IdentityReference) can use this template to request a Subordinate
Certification Authority (SubCA) certificate without Manager Approval.

The resultant certificate can be used by an attacker to instantiate their own
SubCA which is trusted by AD.

By default, certificates created from this attacker-controlled SubCA cannot be
used for authentication, but they can be used for other purposes such as TLS
certs and code signing.

However, if an attacker can modify the NtAuthCertificates object (see ESC5),
they can convert their rogue CA into one trusted for authentication.

"@
                    Fix                   = @"
# Enable Manager Approval
`$Object = `'$($_.DistinguishedName)`'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                    Revert                = @"
# Disable Manager Approval
`$Object = `'$($_.DistinguishedName)`'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
                    Technique             = 'ESC2'
                }
                $Issue
            }
        }
    }
}
