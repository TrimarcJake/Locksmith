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
