function Find-AuditingIssue {
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
        }
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue['Issue']  = $_.AuditFilter
            $Issue['Fix']    = 'N/A'
            $Issue['Revert'] = 'N/A'
        }
        else {
            $Issue['Issue']  = "Auditing is not fully enabled on $($_.CAFullName). Current value is $($_.AuditFilter)"
            $Issue['Fix']    = "certutil.exe -config `'$($_.CAFullname)`' -setreg `'CA\AuditFilter`' 127; Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
            $Issue['Revert'] = "certutil.exe -config $($_.CAFullname) -setreg CA\AuditFilter  $($_.AuditFilter); Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
        }
        $Issue
    }
}
