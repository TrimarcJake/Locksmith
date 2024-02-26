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
                $Issue.Issue  = 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.'
                $Issue.Fix    = "certutil -config $CAFullname -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
                $Issue.Revert = "certutil -config $CAFullname -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
            }
            $Issue
        }
    }
}
