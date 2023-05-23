<#
.SYNOPSIS
Finds the most common malconfigurations of Active Directory Certificate Services (AD CS).

.DESCRIPTION
Locksmith uses the Active Directory (AD) Powershell (PS) module to identify 6 misconfigurations
commonly found in Enterprise mode AD CS installations.

.COMPONENT
Locksmith requires the AD PS module to be installed in the scope of the Current User.
If Locksmith does not identify the AD PS module as installed, it will attempt to 
install the module. If module installation does not complete successfully, 
Locksmith will fail.

.PARAMETER Mode
Specifies sets of common script execution modes.

-Mode 0
Finds any malconfigurations and displays them in the console.
No attempt is made to fix identified issues.

-Mode 1
Finds any malconfigurations and displays them in the console.
Displays example Powershell snippet that can be used to resolve the issue.
No attempt is made to fix identified issues.

-Mode 2
Finds any malconfigurations and writes them to a series of CSV files.
No attempt is made to fix identified issues.

-Mode 3
Finds any malconfigurations and writes them to a series of CSV files.
Creates code snippets to fix each issue and writes them to an environment-specific custom .PS1 file.
No attempt is made to fix identified issues.

-Mode 4
Finds any malconfigurations and creates code snippets to fix each issue.
Attempts to fix all identified issues. This mode may require high-privileged access.

.INPUTS
None. You cannot pipe objects to Invoke-Locksmith.ps1.

.OUTPUTS
Output types:
1. Console display of identified issues
2. Console display of identified issues and their fixes
3. CSV containing all identified issues
4. CSV containing all identified issues and their fixes
#>

# Windows PowerShell cmdlet Restart-Service requires RunAsAdministrator
#Requires -Version 3.0

[CmdletBinding()]
param (
    [string]$Forest,
    [string]$InputPath,
    [int]$Mode = 0,
    [string]$OutputPath = (Get-Location).Path,
    [System.Management.Automation.PSCredential]$Credential   
)

Set-StrictMode -Version Latest

$Logo = "
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.            
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'            
"

# Static variables
$SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
$SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$'
$UnsafeOwners = 'S-1-1-0|-11$|-513$|-515$'
$UnsafeUsers = 'S-1-1-0|-11$|-513$|-515$'
$ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
$DangerousRights = 'GenericAll|WriteDacl|WriteOwner|WriteProperty'
$EnrollmentEndpoints = @("/certsrv/","/<CANAME>_CES_Kerberos/service.svc","/<CANAME>_CES_Kerberos/service.svc/CES","/ADPolicyProvider_CEP_Kerberos/service.svc","/certsrv/mscep/")
$Protocols = @('http://','https://')

# Generated variables
$DNSRoot = [string]((Get-ADForest).RootDomain | Get-ADDomain).DNSRoot
$EnterpriseAdminsSID = ([string]((Get-ADForest).RootDomain | Get-ADDomain).DomainSID) + '-519'
$RootDomainCertPublishersSID = ([string]((Get-ADForest).RootDomain | Get-ADDomain).DomainSID) + '-517'
$RootDomainDomainAdminsSID = ([string]((Get-ADForest).RootDomain | Get-ADDomain).DomainSID) + '-512'
$PreferredOwner = New-Object System.Security.Principal.SecurityIdentifier($EnterpriseAdminsSID)

# Add SIDs of (probably) Safe Users to $SafeUsers
Get-ADGroupMember $EnterpriseAdminsSID | ForEach-Object {
    $SafeUsers += '|' + $_.SID
}

Get-ADGroupMember $RootDomainCertPublishersSID | ForEach-Object {
    $SafeUsers += '|' + $_.SID
}

Get-ADGroupMember $RootDomainDomainAdminsSID | ForEach-Object {
    $SafeUsers += '|' + $_.SID
}

Get-ADGroupMember S-1-5-32-544 | ForEach-Object {
    $SafeUsers += '|' + $_.SID
}


function Test-IsElevated {
    <#
    .SYNOPSIS
        Tests if PowerShell is running with elevated privileges (run as Administrator).
    .DESCRIPTION
        This function returns True if the script is being run as an administrator or False if not.
    .EXAMPLE
        Test-IsElevated
    .EXAMPLE
        if (!(Test-IsElevated)) { Write-Host "You are not running with elevated privileges and will not be able to make any changes." -ForeGroundColor Yellow }
    .EXAMPLE
        # Prompt to launch elevated if not already running as administrator:
        if (!(Test-IsElevated)) {
            $arguments = "& '" + $myinvocation.mycommand.definition + "'"
            Start-Process powershell -Verb runAs -ArgumentList $arguments
            Break
        }
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}


function Test-IsADAdmin {
    <#
    .SYNOPSIS
        Tests if the current user has administrative rights in Active Directory.
    .DESCRIPTION
        This function returns True if the current user is a Domain Admin (or equivalent) or False if not.
    .EXAMPLE
        Test-IsADAdmin
    .EXAMPLE
        if (!(Test-IsADAdmin)) { Write-Host "You are not running with Domain Admin rights and will not be able to make certain changes." -ForeGroundColor Yellow }
    #>
    if (
        # Need to test to make sure this checks domain groups and not local groups, particularly for 'Administrators' (reference SID instead of name?).
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Domain Admin") -or
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators") -or
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins")
       ) {
        Return $true
    }
    else {
        Return $false
    }
}


function Test-IsLocalAccountSession {
    <#
    .SYNOPSIS
        Tests if the current session is running under a local user account or a domain account.
    .DESCRIPTION
        This function returns True if the current session is a local user or False if it is a domain user.
    .EXAMPLE
        Test-IsLocalAccountSession
    .EXAMPLE
        if ( (Test-IsLocalAccountSession) ) { Write-Host "You are running this script under a local account." -ForeGroundColor Yellow }
    #>
    [CmdletBinding()]

    $CurrentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $LocalSIDs = (Get-LocalUser).SID.Value
    if ($CurrentSID -in $LocalSIDs) {
        Return $true
    }
}


function Get-RestrictedAdminModeSetting {
    $Path = 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa'
    try {
        $RAM = (Get-ItemProperty -Path $Path).DisableRestrictedAdmin
        $Creds = (Get-ItemProperty -Path $Path).DisableRestrictedAdminOutboundCreds
        if ($RAM -eq '0' -and $Creds -eq '1'){
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}


function Get-Target {
    param (
        [string]$Forest,
        [string]$InputPath,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Forest) {
        $Targets = $Forest
    }
    elseif ($InputPath) {
        $Targets = Get-Content $InputPath
    } else {
        if ($Credential){
            $Targets = (Get-ADForest -Credential $Credential).Name
        } else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}


function New-OutputPath {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    # Create one output directory per forest
    foreach ( $forest in $Targets ) {
        $ForestPath = $OutputPath + "`\" + $forest
        New-Item -Path $ForestPath -ItemType Directory -Force  | Out-Null
    }
}


function Get-ADCSObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Targets,
        [System.Management.Automation.PSCredential]$Credential
    )
    foreach ( $forest in $Targets ) {
        if ($Credential){
            $ADRoot = (Get-ADRootDSE -Credential $Credential -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties * -Credential $Credential
        } else {
            $ADRoot = (Get-ADRootDSE -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties *
        }
    }
}


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
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $CAEnrollmentEndpoints = @()
        $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
            [string]$CAFullName = "$($_.dNSHostName)\$($_.Name)"
            $CAHostname = $_.dNSHostName.split('.')[0]
            $CAName = $CAFullName.split('\')[1]
            foreach ($Endpoint in $EnrollmentEndpoints) {
                foreach ($Protocol in $Protocols) {
                    $URL = $Protocol + $_.dNSHostName + $Endpoint -replace '<CANAME>', $_.Name
                    $Response = $null
                    if ($Credential) {
                        try { 
                            $Response = Invoke-WebRequest -Method GET -Uri $URL -Credential $Credential -TimeoutSec 3 -UseBasicParsing
                            if ($Response.StatusCode -eq '200') {
                                $CAEnrollmentEndpoints += $URL  
                            }
                        } catch {}
                    } else {
                        try { 
                            $Response = Invoke-WebRequest -Method GET -Uri $URL -UseDefaultCredentials -TimeoutSec 3 -UseBasicParsing
                            if ($Response.StatusCode -eq '200') {
                                $CAEnrollmentEndpoints += $URL  
                            }
                        } catch {}
                    }

                }
            }
            if ($Credential){
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Credential $Credential).DistinguishedName
            } else {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') }).DistinguishedName
            }
            $ping = Test-Connection -ComputerName $CAHostname -Quiet
            if ($ping) {
                try {
                    if ($Credential) {
                        $CertutilAudit = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock {param($CAFullName);certutil -config $CAFullName -getreg CA\AuditFilter} -ArgumentList $CAFullName
                    } else {  
                        $CertutilAudit = certutil -config $CAFullName -getreg CA\AuditFilter
                    }
                } catch {
                    $AuditFilter = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilFlag = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock {param($CAFullName);certutil -config $CAFullName -getreg policy\EditFlags} -ArgumentList $CAFullName
                    } else {
                        $CertutilFlag = certutil -config $CAFullName -getreg policy\EditFlags
                    }
                } catch {
                    $AuditFilter = 'Failure'
                }
            }
            else {
                $AuditFilter = 'CA Unavailable'
                $SANFlag = 'CA Unavailable'
            }
            if ($CertutilAudit) {
                try {
                    [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = ' | Select-String '\('
                    $AuditFilter = $AuditFilter.split('(')[1].split(')')[0]
                }
                catch {
                    try {
                        [string]$AuditFilter = $CertutilAudit | Select-String 'AuditFilter REG_DWORD = '
                        $AuditFilter = $AuditFilter.split('=')[1].trim()
                    }
                    catch {
                        $AuditFilter = 'Never Configured'
                    }
                }
            }
            if ($CertutilFlag) {
                [string]$SANFlag = $CertutilFlag | Select-String ' EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 \('
                if ($SANFlag) {
                    $SANFlag = 'Yes'
                }
                else {
                    $SANFlag = 'No'
                }
            }
            Add-Member -InputObject $_ -MemberType NoteProperty -Name AuditFilter -Value $AuditFilter -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAFullName -Value $CAFullName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostname -Value $CAHostname -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostDistinguishedName -Value $CAHostDistinguishedName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name SANFlag -Value $SANFlag -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name EnrollmentEndpoints -Value $CAEnrollmentEndpoints -Force
        }
    }
}


function Get-CAHostObject {
    [CmdletBinding()]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [System.Management.Automation.PSCredential]$Credential
    )
    process {
        if ($Credential) {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                Get-ADObject $_.CAHostDistinguishedName -Properties * -Credential $Credential
            }
        } else {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                Get-ADObject $_.CAHostDistinguishedName -Properties *
            }
        }
    }
}


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
        $Issue = New-Object -TypeName pscustomobject
        $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
        $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
        $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value $_.AuditFilter -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'DETECT' -Force
        }
        else {
            $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value "Auditing is not fully enabled. Current value is $($_.AuditFilter)" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                -Value "certutil -config `'$($_.CAFullname)`' -setreg `'CA\AuditFilter`' 127; Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                -Value "certutil -config $($_.CAFullname) -setreg CA\AuditFilter  $($_.AuditFilter); Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'DETECT' -Force
        }
        $Issue
    }
}


function Find-ESC1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
        ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
        ($_.'msPKI-Enrollment-Flag' -ne 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC1'
                $Issue
            }
        }
    }
}


function Find-ESC2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [string]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.ObjectClass -eq 'pKICertificateTemplate') -and
        (!$_.pkiExtendedKeyUsage) -and 
        ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
        ($_.'msPKI-Enrollment-Flag' -ne 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') ) 
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) can request a SubCA certificate without Manager Approval" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                    -Value "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC2'
                $Issue
            }
        }
    }
}


function Find-ESC4 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects,
        [Parameter(Mandatory = $true)]
        $DangerousRights,
        [Parameter(Mandatory = $true)]
        $SafeOwners,
        [Parameter(Mandatory = $true)]
        $SafeUsers
    )
    $ADCSObjects | ForEach-Object {
        $Principal = New-Object System.Security.Principal.NTAccount($_.nTSecurityDescriptor.Owner)
        if ($Principal -match '^(S-1|O:)') {
            $SID = $Principal
        } else {
            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }
        if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
            $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                -Value "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value '[TODO]' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC4'
            $Issue
        }
        if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -match $UnsafeOwners) ) {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
            $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                -Value "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC4'
            $Issue
        }
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($_.objectClass -eq 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this template"  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC4'
                $Issue
            }
        }
    }
}


function Find-ESC5 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects,
        [Parameter(Mandatory = $true)]
        $DangerousRights,
        [Parameter(Mandatory = $true)]
        $SafeOwners,
        [Parameter(Mandatory = $true)]
        $SafeUsers
    )
    $ADCSObjects | ForEach-Object {
        $Principal = New-Object System.Security.Principal.NTAccount($_.nTSecurityDescriptor.Owner)
        if ($Principal -match '^(S-1|O:)') {
            $SID = $Principal
        } else {
            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }
        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
            $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                -Value "$($_.nTSecurityDescriptor.Owner) has Owner rights on this object" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value '[TODO]' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC5'
            $Issue
        }
        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -match $UnsafeOwners) ) {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
            $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                -Value "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC5'
            $Issue
        }
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            } else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($_.objectClass -ne 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) ) {
                $Issue = New-Object -TypeName pscustomobject
                $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
                $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
                $Issue | Add-Member -MemberType NoteProperty -Name IdentityReference -Value $entry.IdentityReference -Force
                $Issue | Add-Member -MemberType NoteProperty -Name ActiveDirectoryRights -Value $entry.ActiveDirectoryRights -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Issue `
                    -Value "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this object" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value '[TODO]'  -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC5'
                $Issue
            }
        }
    }
}


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
            $Issue
        }
    }
}


function Find-ESC8 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects
    )
    process {
        $ADCSObjects | Where-Object { 
            $_.EnrollmentEndpoints -ne ''
        } | ForEach-Object {
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            if ($_.EnrollmentEndpoints -like 'http*') {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value 'HTTP enrollment is enabled.' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name EnrollmentEndpoints -Value $_.EnrollmentEndpoints -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "TBD - Remediate by doing 1, 2, and 3" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value "TBD" -Force
            }
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC8'
            $Issue
        }
    }

}


function Export-RevertScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AuditingIssues,
        [Parameter(Mandatory = $true)]
        [array]$ESC1,
        [Parameter(Mandatory = $true)]
        [array]$ESC2,
        [Parameter(Mandatory = $true)]
        [array]$ESC6
    )
    begin {
        $Output = 'Invoke-RevertLocksmith.ps1'
        Set-Content -Path $Output -Value "<#`nScript to revert changes performed by Locksmith`nCreated $(Get-Date)`n#>" -Force
        $Objects = $AuditingIssues + $ESC1 + $ESC2 + $ESC6
    }
    process {
        if ($Objects) {
            $Objects | ForEach-Object {
                Add-Content -Path $Output -Value $_.Revert
                Start-Sleep -Seconds 5
            }
        }
    }
}

function Format-Result {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Issue,
        [Parameter(Mandatory = $true)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT = 'Auditing Issues'
        ESC1   = 'ESC1 - Misconfigured Certificate Template'
        ESC2   = 'ESC2 - Misconfigured Certificate Template'
        ESC4   = 'ESC4 - Vulnerable Certifcate Template Access Control'
        ESC5   = 'ESC5 - Vulnerable PKI Object Access Control'
        ESC6   = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2'
        ESC8   = 'ESC8 - HTTP Enrollment Enabled'
    }

    if ($null -ne $Issue) {
        $UniqueIssue = $Issue.Technique | Sort-Object -Unique
        Write-Host "`n########## $($IssueTable[$UniqueIssue]) ##########`n"
        switch ($Mode) {
            0 {
                $Issue | Format-Table Technique, Name, Issue -Wrap
            }
            1 {
                if ($Issue.Technique -eq 'ESC8') {
                    $Issue | Format-List Technique, Name, DistinguishedName, EnrollmentEndpoints, Issue, Fix
                } else {
                    $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix
                    if(($Issue.Technique -eq "DETECT" -or $Issue.Technique -eq "ESC6") -and (Get-RestrictedAdminModeSetting)){
                        Write-Warning "Restricted Admin Mode appears to be configured. Certutil.exe may not work from this host, therefore you may need to execute the 'Fix' commands on the CA server itself"
                    }
                }
            }
        }
    }
}

if (!$Credential -and (Get-RestrictedAdminModeSetting)) {
    Write-Warning "Restricted Admin Mode appears to be in place, re-run with the '-Credential domain\user' option"
    break;
}

Clear-Host
$Logo
if ($Credential) {
    $Targets = Get-Target -Credential $Credential
} else {
    $Targets = Get-Target
}

# Check if ActiveDirectory PowerShell module is available, and attempt to install if not found
if (-not(Get-Module -Name 'ActiveDirectory' -ListAvailable)) { 
    $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
    # 1 - workstation, 2 - domain controller, 3 - non-dc server
    if ($OS -gt 1) {
        # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
        Install-WindowsFeature -Name RSAT-AD-PowerShell
    } else {
        # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
        Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
    }
}


Clear-Host
$Logo
Write-Host "Gathering AD CS Objects from $($Targets)..."
if ($Credential) {
    $ADCSObjects = Get-ADCSObject -Targets $Targets -Credential $Credential
    Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -Credential $Credential
    $ADCSObjects += Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential
    $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects  -Credential $Credential
    $CAHosts | ForEach-Object { $SafeUsers += '|' + $_.Name }
} else {
    $ADCSObjects = Get-ADCSObject -Targets $Targets
    Set-AdditionalCAProperty -ADCSObjects $ADCSObjects
    $ADCSObjects += Get-CAHostObject -ADCSObjects $ADCSObjects
    $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects
    $CAHosts | ForEach-Object { $SafeUsers += '|' + $_.Name }
}

Clear-Host
$Logo
Write-Host 'Identifying auditing issues...'
[array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects 

Clear-Host
$Logo
Write-Host 'Identifying AD CS templates with dangerous configurations...'
[array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
[array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers

Clear-Host
$Logo
Write-Host 'Identifying AD CS template and other objects with poor access control...'
[array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
[array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
[array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects

Clear-Host
$Logo
Write-Host 'Identifying HTTP-based certificate enrollment interfaces...'
[array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects 

[array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC4 + $ESC5 + $ESC6 + $ESC8

# If these are all empty = no issues found, exit
if ((!$AuditingIssues) -and (!$ESC1) -and (!$ESC2) -and (!$ESC4) -and (!$ESC5) -and (!$ESC6) -and (!$ESC8) ) {
    Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
    break
}

switch ($Mode) {
    0 { 
        Clear-Host
        $Logo
        Format-Result $AuditingIssues '0'  
        Format-Result $ESC1 '0'
        Format-Result $ESC2 '0'
        Format-Result $ESC4 '0'
        Format-Result $ESC5 '0'
        Format-Result $ESC6 '0'
        Format-Result $ESC8 '0'
    }
    1 {
        Clear-Host
        $Logo
        Format-Result $AuditingIssues '1'  
        Format-Result $ESC1 '1'
        Format-Result $ESC2 '1'
        Format-Result $ESC4 '1'
        Format-Result $ESC5 '1'
        Format-Result $ESC6 '1'
        Format-Result $ESC8 '1'
    }
    2 {
        Clear-Host
        $Logo
        $Output = 'ADCSIssues.CSV'
        Write-Host "Writing AD CS issues to $Output..."
        try {
            $AllIssues | Select-Object Forest, Name, Issue | Export-Csv -NoTypeInformation $Output
            Write-Host "$Output created successfully!"
        }
        catch {
            Write-Host 'Ope! Something broke.'
        } 
    }
    3 {
        Clear-Host
        $Logo
        $Output = 'ADCSRemediation.CSV'
        Write-Host "Writing AD CS issues to $Output..."
        try {
            $AllIssues | Select-Object Forest, Name, DistinguishedName, Issue, Fix | Export-Csv -NoTypeInformation $Output
            Write-Host "$Output created successfully!"
        }
        catch {
            Write-Host 'Ope! Something broke.'
        }
    }
    4 {
        Write-Host 'Creating a script to revert any changes made by Locksmith...'
        Export-RevertScript -AuditingIssues $AuditingIssues -ESC1 $ESC1 -ESC2 $ESC2 -ESC6 $ESC6
        Write-Host 'Executing Mode 4 - Attempting to fix all identified issues!'
        if ($AuditingIssues) {
            $AuditingIssues | ForEach-Object {
                Clear-Host
                Write-Host $Logo
                $FixBlock = [scriptblock]::Create($_.Fix)
                Write-Host "Attempting to fully enable AD CS auditing on $($_.Name)..."
                Write-Host "This should have little impact on your environment.`n"
                Write-Host 'Command(s) to be run:'
                Write-Host 'PS> ' -NoNewline
                Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                try {
                    $WarningError = $null
                    Write-Warning 'If you continue, this script will attempt to fix this issue.' -WarningAction Inquire -ErrorVariable WarningError
                    if (!$WarningError) {
                        try {
                            Invoke-Command -ScriptBlock $FixBlock
                        }
                        catch {
                            Write-Error 'Could not modify AD CS auditing. Are you a local admin on this host?'
                        }
                    }
                }
                catch {
                    Write-Host 'SKIPPED!' -ForegroundColor Yellow
                }
                Read-Host -Prompt 'Press any key to continue...'
            }
        }
        if ($ESC1) {
            $ESC1 | ForEach-Object {
                Clear-Host
                Write-Host $Logo
                $FixBlock = [scriptblock]::Create($_.Fix)
                Write-Host "Attempting to enable Manager Approval on the $($_.Name) template...`n"
                Write-Host 'Command(s) to be run:'
                Write-Host 'PS> ' -NoNewline
                Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                try {
                    $WarningError = $null
                    Write-Warning "This could cause some services to stop working until certificates are approved.`nIf you continue this script will attempt to fix this issues." -WarningAction Inquire -ErrorVariable WarningError
                    if (!$WarningError) {
                        try {
                            Invoke-Command -ScriptBlock $FixBlock
                        }
                        catch {
                            Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                        }
                    }
                }
                catch {
                    Write-Host 'SKIPPED!' -ForegroundColor Yellow
                }
                Read-Host -Prompt 'Press any key to continue...'
            }
        }
        if ($ESC2) {
            $ESC2 | ForEach-Object {
                Clear-Host
                Write-Host $Logo
                $FixBlock = [scriptblock]::Create($_.Fix)
                Write-Host "Attempting to enable Manager Approval on the $($_.Name) template...`n"
                Write-Host 'Command(s) to be run:'
                Write-Host 'PS> ' -NoNewline
                Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                try {
                    $WarningError = $null
                    Write-Warning "This could cause some services to stop working until certificates are approved.`nIf you continue, this script will attempt to fix this issue." -WarningAction Inquire -ErrorVariable WarningError
                    if (!$WarningError) {
                        try {
                            Invoke-Command -ScriptBlock $FixBlock
                        }
                        catch {
                            Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                        }
                    }
                }
                catch {
                    Write-Host 'SKIPPED!' -ForegroundColor Yellow
                }
                Read-Host -Prompt 'Press any key to continue...'
            }
        }
        if ($ESC6) {
            $ESC6 | ForEach-Object {
                Clear-Host
                Write-Host $Logo
                $FixBlock = [scriptblock]::Create($_.Fix)
                Write-Host "Attempting to disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on $($_.Name)...`n"
                Write-Host 'Command(s) to be run:'
                Write-Host 'PS> ' -NoNewline
                Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
                try {
                    $WarningError = $null
                    Write-Warning "This could cause some services to stop working.`nIf you continue this script will attempt to fix this issues." -WarningAction Inquire -ErrorVariable WarningError
                    if (!$WarningError) {
                        try {
                            Invoke-Command -ScriptBlock $FixBlock
                        }
                        catch {
                            Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                        }
                    }
                }
                catch {
                    Write-Host 'SKIPPED!' -ForegroundColor Yellow
                }
                Read-Host -Prompt 'Press any key to continue...'
            }
        }
    }
}
