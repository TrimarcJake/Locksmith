function Get-PublishedTemplates {
    <#
    .SYNOPSIS
    Get published certificate templates from Active Directory.

    .DESCRIPTION
    Gets all templates from Active Directory and identifies which ones are published.

    .EXAMPLE
    Get-PublishedTemplates

    .NOTES
        If either of these flags are set, the template is considered published:

        - CT_FLAG_IS_CA      (0x1): This bit indicates whether the template is for a Certification Authority (CA). If this bit is set, the template is considered published.
        - CT_FLAG_IS_DEFAULT (0x2): This bit indicates whether the template is a default template. If this bit is set, the template is also considered published.

        If pkiEnrollmentFlag has 0x10 (CT_FLAG_PUBLISH_TO_DS) set, the certificate is published to Active Directory.
    #>
    [CmdletBinding()]
    param (
        # Use the ADCSObjects already found
        [Parameter(Mandatory,ValueFromPipeline)]
        $ADCSObjects
    )

    #region Get Templates With ADSI Searcher
    $ADSISearcher = [adsisearcher]'(objectClass=*)'
    $ADSISearcher.SearchRoot = [adsi]'LDAP://RootDSE'
    $ConfigurationNamingContext = $ADSISearcher.SearchRoot.Properties['configurationNamingContext'][0]

    # Set the [adsisearcher] filter, search root, and other options
    $ADSISearcher = [adsisearcher]'(objectClass=pKICertificateTemplate)'
    $ADSISearcher.SearchRoot = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigurationNamingContext"

    $Results = $ADSISearcher.FindAll()

    [array]$Templates = @()

    foreach ($item in $Results) {
        $Template = $item.GetDirectoryEntry()
        $TemplateName = $Template.Properties['Name'][0]
        $OID = $item.Properties['mspki-cert-template-oid'][0]
        $Flags = $Template.Properties['flags'][0]
        $EnrollmentFlag = $item.Properties['mspki-enrollment-flag'][0]
        $LastModified = $item.Properties['whenchanged'][0]
        $Revision = $item.Properties['Revision'][0]
        $MinorRevision = $item.Properties['mspki-template-minor-revision'][0]

        # Check if the template is published
        $IsPublished = (($Flags -band 0x1) -ne 0 -or ($Flags -band 0x2) -ne 0) -or ($EnrollmentFlag -band 0x10)

        $Templates += (
            [PSCustomObject]@{
                Name = $TemplateName
                OID = $OID
                Flags = $Flags
                EnrollmentFlag = $EnrollmentFlag
                IsPublished = $IsPublished
                LastModified = $LastModified
                Revision = $Revision
                MinorRevision = $MinorRevision
            }
        )
    }
    #endregion Get Templates With ADSI Searcher

    $Templates = $ADCSObjects.Where({$_.objectClass -eq 'pKICertificateTemplate'}) | Sort-Object Name
    $PublishedTemplates = $ADCSObjects.Where({$_.displayName})


    return $Templates | Where-Object {$_.IsPublished -eq $true}
}
