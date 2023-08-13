function Set-AdditionalCAProperty {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [System.Management.Automation.PSCredential]$Credential
    )
    process {
        $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
            [string]$CAEnrollmentEndpoint = $_.'msPKI-Enrollment-Servers' | Select-String 'http.*' | ForEach-Object { $_.Matches[0].Value }
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $CAHostname = $_.dNSHostName.split('.')[0]
            # $CAName = $_.Name
            if ($Credential) {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC -Credential $Credential).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC -Credential $Credential).DnsHostname
            } else {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC ).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC).DnsHostname
            }
            $ping = Test-Connection -ComputerName $CAHostFQDN -Quiet -Count 1
            if ($ping) {
                try {
                    if ($Credential) {
                        $CertutilAudit = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock { param($CAFullName); certutil -config $CAFullName -getreg CA\AuditFilter } -ArgumentList $CAFullName
                    } else {
                        $CertutilAudit = certutil -config $CAFullName -getreg CA\AuditFilter
                    }
                } catch {
                    $AuditFilter = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilFlag = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock { param($CAFullName); certutil -config $CAFullName -getreg policy\EditFlags } -ArgumentList $CAFullName
                    } else {
                        $CertutilFlag = certutil -config $CAFullName -getreg policy\EditFlags
                    }
                } catch {
                    $AuditFilter = 'Failure'
                }
            } else {
                $AuditFilter = 'CA Unavailable'
                $SANFlag = 'CA Unavailable'
            }
            if ($CertutilAudit) {
                try {
                    [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
                    $AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
                } catch {
                    try {
                        [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
                        $AuditFilter = $AuditFilter.split('=')[1].trim()
                    } catch {
                        $AuditFilter = 'Never Configured'
                    }
                }
            }
            if ($CertutilFlag) {
                [string]$SANFlag = $CertutilFlag | Select-String ' EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 \('
                if ($SANFlag) {
                    $SANFlag = 'Yes'
                } else {
                    $SANFlag = 'No'
                }
            }
            Add-Member -InputObject $_ -MemberType NoteProperty -Name AuditFilter -Value $AuditFilter -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAEnrollmentEndpoint -Value $CAEnrollmentEndpoint -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAFullName -Value $CAFullName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostname -Value $CAHostname -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostDistinguishedName -Value $CAHostDistinguishedName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name SANFlag -Value $SANFlag -Force
        }
    }
}