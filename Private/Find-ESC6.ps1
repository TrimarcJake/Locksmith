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
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            if ($_.SANFlag -eq 'Yes') {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "certutil -config $CAFullname -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "certutil -config $CAFullname -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            }
            else {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value $_.AuditFilter -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value 'N/A' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value 'N/A' -Force
            }
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC6'
            $Severity = Set-Severity -Issue $Issue
            $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
            $Issue
        }
    }
}