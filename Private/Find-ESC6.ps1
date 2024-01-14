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
            $Issue | Add-Member -MemberType NoteProperty -Name Forest = $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name = $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName = $_.DistinguishedName -Force
            if ($_.SANFlag -eq 'Yes') {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue = 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix = "certutil -config $CAFullname -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert = "certutil -config $CAFullname -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            }
            else {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue = $_.AuditFilter -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix = 'N/A' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert = 'N/A' -Force
            }
            $Issue | Add-Member -MemberType NoteProperty -Name Technique = 'ESC6'
            $Severity = Set-Severity -Issue $Issue
            $Issue | Add-Member -MemberType NoteProperty -Name Severity = $Severity
            $Issue
        }
    }
}
