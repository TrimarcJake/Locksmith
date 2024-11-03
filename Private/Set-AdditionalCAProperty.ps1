﻿function Set-AdditionalCAProperty {
    <#
    .SYNOPSIS
        Sets additional properties for a Certificate Authority (CA) object.

    .DESCRIPTION
        This script sets additional properties for a Certificate Authority (CA) object.
        It takes an array of AD CS Objects as input, which represent the CA objects to be processed.
        The script filters the AD CS Objects based on the objectClass property and performs the necessary operations
        to set the additional properties.

    .PARAMETER ADCSObjects
        Specifies the array of AD CS Objects to be processed. This parameter is mandatory and supports pipeline input.

    .PARAMETER Credential
        Specifies the PSCredential object to be used for authentication when accessing the CA objects.
        If not provided, the script will use the current user's credentials.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObject -Filter
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -ForestGC 'dc1.ad.dotdot.horse:3268'

    .NOTES
        Author: Jake Hildreth
        Date: July 15, 2022
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [PSCredential]$Credential,
        $ForestGC
    )

    begin {
        $CAEnrollmentEndpoint = @()
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy') ) {
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                $code= @"
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
                            return true;
                        }
                    }
"@
                Add-Type -TypeDefinition $code -Language CSharp
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            } else {
                Add-Type @"
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    using System.Net.Security;
                    public class TrustAllCertsPolicy {
                        public static bool TrustAllCerts(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
                            return true;
                        }
                    }
"@
                # Set the ServerCertificateValidationCallback
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [TrustAllCertsPolicy]::TrustAllCerts
            }
        }
    }

    process {
        $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
            #[array]$CAEnrollmentEndpoint = $_.'msPKI-Enrollment-Servers' | Select-String 'http.*' | ForEach-Object { $_.Matches[0].Value }
            foreach ($directory in @("certsrv/", "$($_.Name)_CES_Kerberos/service.svc", "$($_.Name)_CES_Kerberos/service.svc/CES", "ADPolicyProvider_CEP_Kerberos/service.svc", "certsrv/mscep/")) {
                $URL = "://$($_.dNSHostName)/$directory"
                try {
                    $Auth = 'NTLM'
                    $FullURL = "http$URL"
                    $Request = [System.Net.WebRequest]::Create($FullURL)
                    $Cache = [System.Net.CredentialCache]::New()
                    $Cache.Add([System.Uri]::new($FullURL), $Auth, [System.Net.CredentialCache]::DefaultNetworkCredentials)
                    $Request.Credentials = $Cache
                    $Request.Timeout = 3000
                    $Request.GetResponse() | Out-Null
                    $CAEnrollmentEndpoint += @{
                        'URL'  = $FullURL
                        'Auth' = $Auth
                    }
                } catch {
                    try {
                        $FullURL = "https$URL"
                        $Request = [System.Net.WebRequest]::Create($FullURL)

                        $Request.GetResponse() | Out-Null
                        $CAEnrollmentEndpoint += @{
                            'URL'  = $FullURL
                            'Auth' = $Auth
                        }
                    } catch {
                        try {
                            $Auth = 'Negotiate'
                            $FullURL = "https$URL"
                            $Request = [System.Net.WebRequest]::Create($FullURL)
                            $Cache = [System.Net.CredentialCache]::New()
                            $Cache.Add([System.Uri]::new($FullURL), 'Negotiate', [System.Net.CredentialCache]::DefaultNetworkCredentials)
                            $Request.Credentials = $Cache
                            $Request.GetResponse() | Out-Null
                            $CAEnrollmentEndpoint += @{
                                'URL'  = $FullURL
                                'Auth' = $Auth
                            }
                        } catch {
                        }
                    }
                }
            }
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $CAHostname = $_.dNSHostName.split('.')[0]
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
