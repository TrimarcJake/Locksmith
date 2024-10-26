function Find-ESC11 {
    <#
    .SYNOPSIS
        This script finds AD CS (Active Directory Certificate Services) objects that have the ESC11 vulnerability.

    .DESCRIPTION
        The script takes an array of ADCS objects as input and filters them based on objects that have the objectClass
        'pKIEnrollmentService' and the InterfaceFlag set to 'No'. For each matching object, it creates a custom object with
        properties representing various information about the object, such as Forest, Name, DistinguishedName, Technique,
        Issue, Fix, and Revert.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to be processed. This parameter is mandatory.

    .OUTPUTS
        The script outputs an array of custom objects representing the matching ADCS objects and their associated information.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Target (Get-Target)
        Find-ESC11 -ADCSObjects $ADCSObjects
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
            ($_.InterfaceFlag -ne 'Yes')
        } | ForEach-Object {
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Technique         = 'ESC11'
                Issue             = $_.AuditFilter
                Fix               = 'N/A'
                Revert            = 'N/A'
            }
            if ($_.InterfaceFlag -eq 'No') {
                $Issue.Issue  = 'IF_ENFORCEENCRYPTICERTREQUEST is disabled.'
                $Issue.Fix    = @"
certutil -config $CAFullname -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock {
    Get-Service -Name `'certsvc`' | Restart-Service -Force
}
"@
                $Issue.Revert = @"
certutil -config $CAFullname -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST
Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock {
    Get-Service -Name `'certsvc`' | Restart-Service -Force
}
"@
            }
            $Issue
        }
    }
}
