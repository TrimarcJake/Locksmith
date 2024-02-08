param (
    [int]$Mode,
    [Parameter()]
    [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe')]
    [array]$Scans = 'All'
)
function ConvertFrom-IdentityReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Object
    )

    $Principal = New-Object System.Security.Principal.NTAccount($Object)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    }
    else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    return $SID
}
function Export-RevertScript {
    [CmdletBinding()]
    param(
        [array]$AuditingIssues,
        [array]$ESC1,
        [array]$ESC2,
        [array]$ESC3,
        [array]$ESC4,
        [array]$ESC5,
        [array]$ESC6
    )
    begin {
        $Output = 'Invoke-RevertLocksmith.ps1'
        Set-Content -Path $Output -Value "<#`nScript to revert changes performed by Locksmith`nCreated $(Get-Date)`n#>" -Force
        $Objects = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6
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
            Issue             = "Auditing is not fully enabled on $($_.CAFullName). Current value is $($_.AuditFilter)"
            Fix               = "certutil.exe -config `'$($_.CAFullname)`' -setreg `'CA\AuditFilter`' 127; Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
            Revert            = "certutil.exe -config $($_.CAFullname) -setreg CA\AuditFilter  $($_.AuditFilter); Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
        }
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue.Issue = $_.AuditFilter
            $Issue.Fix = 'N/A'
            $Issue.Revert = 'N/A'
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
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC1'
                }
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
        ( (!$_.pkiExtendedKeyUsage) -or ($_.pkiExtendedKeyUsage -match '2.5.29.37.0') ) -and
        ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can request a SubCA certificate without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC2'
                }
                $Issue
            }
        }
    }
}

function Find-ESC3Condition1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $EnrollmentAgentEKU) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ( ($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature') )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can enroll in this Enrollment Agent template without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC3'
                }
                $Issue
            }
        }
    }
}

function Find-ESC3Condition2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects,
        [Parameter(Mandatory = $true)]
        [array]$SafeUsers
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($_.pkiExtendedKeyUsage -match $ClientAuthEKU) -and
        ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
        !($_.'msPKI-Enrollment-Flag' -band 2) -and
        ($_.'msPKI-RA-Application-Policies' -eq '1.3.6.1.4.1.311.20.2.1') -and
        ( ($_.'msPKI-RA-Signature' -eq 1) )
    } | ForEach-Object {
        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($SID -notmatch $SafeUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"
                    Fix                   = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}"
                    Revert                = "Get-ADObject `'$($_.DistinguishedName)`' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}"
                    Technique             = 'ESC3'
                }
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
        }
        else {
            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }

        if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -match $UnsafeOwners) ) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $entry.IdentityReference
                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix                   = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Revert                = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Technique             = 'ESC4'
            }
            $Issue
        }
        elseif ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -notmatch $SafeOwners) ) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $entry.IdentityReference
                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix                   = '[TODO]'
                Revert                = '[TODO]'
                Technique             = 'ESC4'
            }
            $Issue
        }

        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($_.objectClass -eq 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) -and
                ($entry.ActiveDirectoryRights.ObjectType -notmatch $SafeObjectTypes)
            ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this template"
                    Fix                   = "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }"
                    Revert                = '[TODO]'
                    Technique             = 'ESC4'
                }
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
        }
        else {
            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }
        if ( ($_.objectClass -ne 'pKICertificateTemplate') -and ($SID -match $UnsafeOwners) ) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $entry.IdentityReference
                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
                Fix                   = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$PreferredOwner`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Revert                = "`$Owner = New-Object System.Security.Principal.SecurityIdentifier(`'$($_.nTSecurityDescriptor.Owner)`'); `$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; `$ACL.SetOwner(`$Owner); Set-ACL -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL"
                Technique             = 'ESC5'
            }
            $Issue
        }
        elseif ( ($_.objectClass -ne 'pKICertificateTemplate') -and
            ($SID -notmatch $SafeOwners) -and
            ($entry.ActiveDirectoryRights.ObjectType -notmatch $SafeObjectTypes)
        ) {
            $Issue = [pscustomobject]@{
                Forest                = $_.CanonicalName.split('/')[0]
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $entry.IdentityReference
                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this object"
                Fix                   = '[TODO]'
                Revert                = '[TODO]'
                Technique             = 'ESC5'
            }
            $Issue
        }

        foreach ($entry in $_.nTSecurityDescriptor.Access) {
            $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
            if ($Principal -match '^(S-1|O:)') {
                $SID = $Principal
            }
            else {
                $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
            }
            if ( ($_.objectClass -ne 'pKICertificateTemplate') -and
                ($SID -notmatch $SafeUsers) -and
                ($entry.ActiveDirectoryRights -match $DangerousRights) ) {
                $Issue = [pscustomobject]@{
                    Forest                = $_.CanonicalName.split('/')[0]
                    Name                  = $_.Name
                    DistinguishedName     = $_.DistinguishedName
                    IdentityReference     = $entry.IdentityReference
                    ActiveDirectoryRights = $entry.ActiveDirectoryRights
                    Issue                 = "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this object"
                    Fix                   = "`$ACL = Get-Acl -Path `'AD:$($_.DistinguishedName)`'; foreach ( `$ace in `$ACL.access ) { if ( (`$ace.IdentityReference.Value -like '$($Principal.Value)' ) -and ( `$ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) { `$ACL.RemoveAccessRule(`$ace) | Out-Null ; Set-Acl -Path `'AD:$($_.DistinguishedName)`' -AclObject `$ACL } }"
                    Revert                = '[TODO]'
                    Technique             = 'ESC5'
                }
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
                $Issue.Issue = 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.'
                $Issue.Fix = "certutil -config $CAFullname -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
                $Issue.Revert = "certutil -config $CAFullname -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName `"$($_.dNSHostName)`" -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }"
            }
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
            $_.CAEnrollmentEndpoint
        } | ForEach-Object {
            $Issue = [pscustomobject]@{
                Forest               = $_.CanonicalName.split('/')[0]
                Name                 = $_.Name
                DistinguishedName    = $_.DistinguishedName
                CAEnrollmentEndpoint = $_.CAEnrollmentEndpoint
                Issue                = 'HTTP enrollment is enabled.'
                Fix                  = '[TODO]'
                Revert               = '[TODO]'
                Technique            = 'ESC8'
            }
            if ($_.CAEnrollmentEndpoint -like '^https*') {
                $Issue.Issue = 'HTTPS enrollment is enabled.'
            }
            $Issue
        }
    }
}

function Format-Result {
    [CmdletBinding()]
    param(
        $Issue,
        [Parameter(Mandatory = $true)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT = 'Auditing Not Fully Enabled'
        ESC1   = 'ESC1 - Vulnerable Certificate Template - Authentication'
        ESC2   = 'ESC2 - Vulnerable Certificate Template - Subordinate CA'
        ESC3   = 'ESC3 - Vulnerable Certificate Template - Enrollment Agent'
        ESC4   = 'ESC4 - Vulnerable Access Control - Certifcate Template'
        ESC5   = 'ESC5 - Vulnerable Access Control - PKI Object'
        ESC6   = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled'
        ESC8   = 'ESC8 - HTTP/S Enrollment Enabled'
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
                    $Issue | Format-List Technique, Name, DistinguishedName, CAEnrollmentEndpoint, Issue, Fix
                }
                else {
                    $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix
                    if (($Issue.Technique -eq "DETECT" -or $Issue.Technique -eq "ESC6") -and (Get-RestrictedAdminModeSetting)) {
                        Write-Warning "Restricted Admin Mode appears to be configured. Certutil.exe may not work from this host, therefore you may need to execute the 'Fix' commands on the CA server itself"
                    }
                }
            }
        }
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
        if ($Credential) {
            $ADRoot = (Get-ADRootDSE -Credential $Credential -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties * -Credential $Credential
        }
        else {
            $ADRoot = (Get-ADRootDSE -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties *
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
                Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC -Credential $Credential
            }
        }
        else {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC
            }
        }
    }
}
function Get-RestrictedAdminModeSetting {
    $Path = 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa'
    try {
        $RAM = (Get-ItemProperty -Path $Path).DisableRestrictedAdmin
        $Creds = (Get-ItemProperty -Path $Path).DisableRestrictedAdminOutboundCreds
        if ($RAM -eq '0' -and $Creds -eq '1') {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
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
    }
    else {
        if ($Credential) {
            $Targets = (Get-ADForest -Credential $Credential).Name
        }
        else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}
function Install-RSATADPowerShell {
    <#
    .SYNOPSIS
        Installs the RSAT AD PowerShell module.
    .DESCRIPTION
        This function checks if the current process is elevated and if it is it will prompt to install the RSAT AD PowerShell module.
    .EXAMPLE
        Install-RSATADPowerShell
    #>
    if (Test-IsElevated) {
        $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        # 1 - workstation, 2 - domain controller, 3 - non-dc server
        if ($OS -gt 1) {
            Write-Warning "The Active Directory PowerShell module is not installed."
            Write-Host "If you continue, Locksmith will attempt to install the Active Directory PowerShell module for you.`n" -ForegroundColor Yellow
            Write-Host "`nCOMMAND: Install-WindowsFeature -Name RSAT-AD-PowerShell`n" -ForegroundColor Cyan
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
                    Install-WindowsFeature -Name RSAT-AD-PowerShell
                }
                catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            }
            else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        }
        else {
            Write-Warning "The Active Directory PowerShell module is not installed."
            Write-Host "If you continue, Locksmith will attempt to install the Active Directory PowerShell module for you.`n" -ForegroundColor Yellow
            Write-Host "`nCOMMAND: Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online`n" -ForegroundColor Cyan
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
                    Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
                }
                catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            }
            else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        }
    }
    else {
        Write-Warning -Message "The ActiveDirectory PowerShell module is required for Locksmith, but is not installed. Please launch an elevated PowerShell session to have this module installed for you automatically."
        # The goal here is to exit the script without closing the PowerShell window. Need to test.
        Return
    }
}
function Invoke-Remediation {
    <#
    .SYNOPSIS
    Runs any remediation scripts available.

    .DESCRIPTION
    This function offers to run any remediation code associated with identified issues.

    .PARAMETER AuditingIssues
    A PS Object containing all necessary information about auditing issues.

    .PARAMETER ESC1
    A PS Object containing all necessary information about ESC1 issues.

    .PARAMETER ESC2
    A PS Object containing all necessary information about ESC2 issues.

    .PARAMETER ESC3
    A PS Object containing all necessary information about ESC3 issues.

    .PARAMETER ESC4
    A PS Object containing all necessary information about ESC4 issues.

    .PARAMETER ESC5
    A PS Object containing all necessary information about ESC5 issues.

    .PARAMETER ESC6
    A PS Object containing all necessary information about ESC6 issues.

    .INPUTS
    PS Objects

    .OUTPUTS
    Console output
    #>

    [CmdletBinding()]
    param (
        $AuditingIssues,
        $ESC1,
        $ESC2,
        $ESC3,
        $ESC4,
        $ESC5,
        $ESC6
    )

    Write-Host "`nExecuting Mode 4 - Attempting to fix identified issues!`n" -ForegroundColor Green
    Write-Host 'Creating a script (' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1' -ForegroundColor White -NoNewline
    Write-Host ") which can be used to revert all changes made by Locksmith...`n"
    try {
        Export-RevertScript -AuditingIssues $AuditingIssues -ESC1 $ESC1 -ESC2 $ESC2 -ESC3 $ESC3 -ESC4 $ESC4 -ESC5 $ESC5 -ESC6 $ESC6
    }
    catch {
        Write-Warning 'Creation of Invoke-RevertLocksmith.ps1 failed.'
        Write-Host "Continue with this operation? [Y] Yes " -NoNewline
        Write-Host "[N] " -ForegroundColor Yellow -NoNewline
        Write-Host "No: " -NoNewline
        $WarningError = ''
        $WarningError = Read-Host
        if ($WarningError -like 'y') {
            # Continue
        }
        else {
            break
        }
    }
    if ($AuditingIssues) {
        $AuditingIssues | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "Auditing is not fully enabled on Certification Authority `"$($_.Name)`".`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to fully enable auditing on Certification Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not modify AD CS auditing. Are you a local admin on the CA host?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC1) {
        $ESC1 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "Security Principals can enroll in `"$($_.Name)`" template using a Subject Alternative Name without Manager Approval.`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'CCOMMAND(S) TO BE RUN:'
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC2) {
        $ESC2 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "Security Principals can enroll in `"$($_.Name)`" template and create a Subordinate Certification Authority without Manager Approval.`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to enable Manager Approval on the `"$($_.Name)`" template.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working until certificates are approved.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not enable Manager Approval. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC4) {
        $ESC4 | Where-Object Issue -Like "* Owner rights *" | ForEach-Object { # This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" template to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC5) {
        $ESC5 | Where-Object Issue -Like "* Owner rights *" | ForEach-Object { # This selector sucks - Jake
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "$($_.Issue)`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to set the owner of `"$($_.Name)`" object to Enterprise Admins.`n"
            Write-Host 'COMMAND(S) TO BE RUN:' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not change Owner. Are you an Active Directory admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }
    if ($ESC6) {
        $ESC6 | ForEach-Object {
            $FixBlock = [scriptblock]::Create($_.Fix)
            Write-Host 'ISSUE:' -ForegroundColor White
            Write-Host "The Certification Authority `"$($_.Name)`" has the dangerous EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.`n"
            Write-Host 'TECHNIQUE:' -ForegroundColor White
            Write-Host "$($_.Technique)`n"
            Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
            Write-Host "Locksmith will attempt to disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on Certifiction Authority `"$($_.Name)`".`n"
            Write-Host 'COMMAND(S) TO BE RUN' -ForegroundColor White
            Write-Host 'PS> ' -NoNewline
            Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
            $WarningError = 'n'
            Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
            Write-Host "WARNING: This change could cause some services to stop working.`n" -ForegroundColor Yellow
            Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Invoke-Command -ScriptBlock $FixBlock
                }
                catch {
                    Write-Error 'Could not disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Are you an Active Directory or AD CS admin?'
                }
            }
            else {
                Write-Host "SKIPPED!`n" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "Mode 4 Complete! There are no more issues that Locksmith can automatically resolve.`n" -ForegroundColor Green
    Write-Host 'If you experience any operational impact from using Locksmith Mode 4, use ' -NoNewline
    Write-Host 'Invoke-RevertLocksmith.ps1 ' -ForegroundColor White
    Write-Host "to revert all changes made by Locksmith. It can be found in the current working directory.`n"
    Write-Host @"
REMINDER: Locksmith cannot automatically resolve all AD CS issues at this time.
There may be more AD CS issues remaining in your environment.
Use Locksmith in Modes 0-3 to further investigate your environment
or reach out to the Locksmith team for assistance. We'd love to help!`n
"@ -ForegroundColor Yellow
}

function Invoke-Scans {
    [CmdletBinding()]
    param (
        # Could split Scans and PromptMe into separate parameter sets.
        [Parameter()]
        [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe')]
        [array]$Scans = 'All'
    )

    # Is this needed?
    if ($Scans -eq $IsNullOrEmpty) {
        $Scans = 'All'
    }

    if ( $Scans -eq 'PromptMe' ) {
        $GridViewTitle = 'Select the tests to run and press Enter or click OK to continue...'

        # Check for Out-GridView or Out-ConsoleGridView
        if ((Get-Command Out-ConsoleGridView -ErrorAction SilentlyContinue) -and ($PSVersionTable.PSVersion.Major -ge 7)) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-ConsoleGridView -OutputMode Multiple -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        else {
            # To Do: Check for admin and prompt to install features/modules or revert to 'All'.
            Write-Information "Out-GridView and Out-ConsoleGridView were not found on your system. Defaulting to `'All`'."
            $Scans = 'All'
        }
    }

    switch ( $Scans ) {
        Auditing {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
        }
        ESC1 {
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC2 {
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC3 {
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC4 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
        }
        ESC5 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
        }
        ESC6 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
        }
        ESC8 {
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
        All {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
    }

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC8

    # If these are all empty = no issues found, exit
    if ((!$AuditingIssues) -and (!$ESC1) -and (!$ESC2) -and (!$ESC3) -and (!$ESC4) -and (!$ESC5) -and (!$ESC6) -and (!$ESC8) ) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
        break
    }

    # Return a hash table of array names (keys) and arrays (values) so they can be directly referenced with other functions
    Return @{
        AllIssues      = $AllIssues
        AuditingIssues = $AuditingIssues
        ESC1           = $ESC1
        ESC2           = $ESC2
        ESC3           = $ESC3
        ESC4           = $ESC4
        ESC5           = $ESC5
        ESC6           = $ESC6
        ESC8           = $ESC8
    }
}

<#
.SYNOPSIS
Create a dictionary of the escalation paths and insecure configurations that Locksmith scans for.

.DESCRIPTION
The New-Dictionary function is used to instantiate an array of objects that contain the names, definitions,
descriptions, code used to find, code used to fix, and reference URLs. This is invoked by the module's main function.

.NOTES

    VulnerableConfigurationItem Class Definition:
        Version         Update each time the class definition or the dictionary below is changed.
        Name            The short name of the vulnerable configuration item (VCI).
        Category        The high level category of VCI types, including escalation path, server configuration, GPO setting, etc.
        Subcategory     The subcategory of vulnerable configuration item types.
        Summary         A summary of the vulnerability and how it can be abused.
        FindIt          The name of the function that is used to look for the VCI, stored as an invokable scriptblock.
        FixIt           The name of the function that is used to fix the VCI, stored as an invokable scriptblock.
        ReferenceUrls   An array of URLs that are used as references to learn more about the VCI.
#>

function New-Dictionary {
    class VulnerableConfigurationItem {
        static [string] $Version = '2023.10.01.000'
        [string]$Name
        [ValidateSet('Escalation Path', 'Server Configuration', 'GPO Setting')][string]$Category
        [string]$Subcategory
        [string]$Summary
        [scriptblock]$FindIt
        [scriptblock]$FixIt
        [uri[]]$ReferenceUrls
    }

    [VulnerableConfigurationItem[]]$Dictionary = @(
        [VulnerableConfigurationItem]@{
            Name          = 'ESC1'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Client Authentication Templates'
            Summary       = ''
            FindIt        = { Find-ESC1 }
            FixIt         = { Write-Output "Add code to fix the vulnerable configuration." }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC1'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC2'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable SubCA/Any Purpose Templates'
            Summary       = ''
            FindIt        = { Find-ESC2 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC2'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC3'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Enrollment Agent Templates'
            Summary       = ''
            FindIt        = {
                Find-ESC3Condition1
                Find-ESC3Condition2
            }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Enrollment%20Agent%20Templates%20%E2%80%94%20ESC3'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC4';
            Category      = 'Escalation Path'
            Subcategory   = 'Certificate Templates with Vulnerable Access Controls'
            Summary       = ''
            FindIt        = { Find-ESC4 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Template%20Access%20Control%20%E2%80%94%20ESC4'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC5';
            Category      = 'Escalation Path'
            Subcategory   = 'PKI Objects with Vulnerable Access Control'
            Summary       = ''
            FindIt        = { Find-ESC5 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20PKI%20Object%20Access%20Control%20%E2%80%94%20ESC5'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC6'
            Category      = 'Escalation Path'
            Subcategory   = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
            Summary       = ''
            FindIt        = { Find-ESC6 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=EDITF_ATTRIBUTESUBJECTALTNAME2%20%E2%80%94%20ESC6'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC7'
            Category      = 'Escalation Path'
            Subcategory   = 'Vulnerable Certificate Authority Access Control'
            Summary       = ''
            FindIt        = { Write-Output 'We have not created Find-ESC7 yet.' }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Authority%20Access%20Control%20%E2%80%94%20ESC7'
        },
        [VulnerableConfigurationItem]@{
            Name          = 'ESC8'
            Category      = 'Escalation Path'
            Subcategory   = 'AD CS HTTP Endpoints Vulnerable to NTLM Relay'
            Summary       = ''
            FindIt        = { Find-ESC8 }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=NTLM%20Relay%20to%20AD%20CS%20HTTP%20Endpoints'
        },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC9'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC9}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC10'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC10}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC11'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC11}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        [VulnerableConfigurationItem]@{
            Name          = 'Auditing'
            Category      = 'Server Configuration'
            Subcategory   = 'Gaps in auditing on certificate authorities and AD CS objects.'
            Summary       = ''
            FindIt        = { Find-AuditingIssue }
            FixIt         = { Write-Output 'Add code to fix the vulnerable configuration.' }
            ReferenceUrls = @('https://github.com/TrimarcJake/Locksmith', 'https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/designing-and-implementing-a-pki-part-i-design-and-planning/ba-p/396953')
        }
    )
    Return $Dictionary
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
function Set-AdditionalCAProperty {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [PSCredential]$Credential
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
            }
            else {
                $CAHostDistinguishedName = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Server $ForestGC ).DistinguishedName
                $CAHostFQDN = (Get-ADObject -Filter { (Name -eq $CAHostName) -and (objectclass -eq 'computer') } -Properties DnsHostname -Server $ForestGC).DnsHostname
            }
            $ping = Test-Connection -ComputerName $CAHostFQDN -Quiet -Count 1
            if ($ping) {
                try {
                    if ($Credential) {
                        $CertutilAudit = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock { param($CAFullName); certutil -config $CAFullName -getreg CA\AuditFilter } -ArgumentList $CAFullName
                    }
                    else {
                        $CertutilAudit = certutil -config $CAFullName -getreg CA\AuditFilter
                    }
                }
                catch {
                    $AuditFilter = 'Failure'
                }
                try {
                    if ($Credential) {
                        $CertutilFlag = Invoke-Command -ComputerName $CAHostname -Credential $Credential -ScriptBlock { param($CAFullName); certutil -config $CAFullName -getreg policy\EditFlags } -ArgumentList $CAFullName
                    }
                    else {
                        $CertutilFlag = certutil -config $CAFullName -getreg policy\EditFlags
                    }
                }
                catch {
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
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAEnrollmentEndpoint -Value $CAEnrollmentEndpoint -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAFullName -Value $CAFullName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostname -Value $CAHostname -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name CAHostDistinguishedName -Value $CAHostDistinguishedName -Force
            Add-Member -InputObject $_ -MemberType NoteProperty -Name SANFlag -Value $SANFlag -Force
        }
    }
}

function Set-Severity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Issue
    )
    foreach ($Finding in $Issue) {
        try {
            # Auditing
            if ($Finding.Technique -eq 'DETECT') {
                return 'Medium'
            }
            # ESC6
            if ($Finding.Technique -eq 'ESC6') {
                return 'High'
            }
            # ESC8
            if ($Finding.Technique -eq 'ESC8') {
                return 'High'
            }
            # ESC1, ESC2, ESC4, ESC5
            $SID = ConvertFrom-IdentityReference -Object $Finding.IdentityReference
            if ($SID -match $SafeUsers -or $SID -match $SafeOwners) {
                return 'Medium'
            }
            if (($SID -notmatch $SafeUsers -and $SID -notmatch $SafeOwners) -and ($Finding.ActiveDirectoryRights -match $DangerousRights)) {
                return 'Critical'
            }
        }
        catch {
            Write-Error "Could not determine issue severity for issue: $($Issue.Issue)"
            return 'Unknown Failure'
        }
    }
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

function Test-IsMemberOfProtectedUsers {
    <#
    .SYNOPSIS
    Check to see if a user is a member of the Protected Users group.

    .DESCRIPTION
    This function checks to see if a specified user or the current user is a member of the Protected Users group in AD.

    .PARAMETER User
    The user that will be checked for membership in the Protected Users group. This parameter accepts input from the pipeline.

    .EXAMPLE
    This example will check if JaneDoe is a member of the Protected Users group.

        Test-IsMemberOfProtectedUsers -User JaneDoe

    .EXAMPLE
    This example will check if the current user is a member of the Protected Users group.

        Test-IsMemberOfProtectedUsers

    .INPUTS
    Active Directory user object, user SID, SamAccountName, etc

    .OUTPUTS
    Boolean

    .NOTES
    Membership in Active Directory's Protect Users group can have implications for anything that relies on NTLM authentication.

#>

    [CmdletBinding()]
    param (
        # User parameter accepts any input that is valid for Get-ADUser
        [Parameter(
            ValueFromPipeline = $true
        )]
        $User
    )

    Import-Module ActiveDirectory

    # Use the currently logged in user if none is specified
    # Get the user from Active Directory
    if (-not($User)) {
        $CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[-1]
        $CheckUser = Get-ADUser $CurrentUser
    }
    else {
        $CheckUser = Get-ADUser $User
    }

    # Get the Protected Users group by SID instead of by its name to ensure compatibility with any locale or language.
    $DomainSID = (Get-ADDomain).DomainSID.Value
    $ProtectedUsersSID = "$DomainSID-525"

    # Get members of the Protected Users group for the current domain. Recuse in case groups are nested in it.
    $ProtectedUsers = Get-ADGroupMember -Identity $ProtectedUsersSID -Recursive | Select-Object -Unique

    # Check if the current user is in the 'Protected Users' group
    if ($ProtectedUsers -contains $CheckUser) {
        Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is a member of the Protected Users group."
        $true
    }
    else {
        Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is not a member of the Protected Users group."
        $false
    }
}

function Test-IsRSATInstalled {
    <#
    .SYNOPSIS
        Tests if the RSAT AD PowerShell module is installed.
    .DESCRIPTION
        This function returns True if the RSAT AD PowerShell module is installed or False if not.
    .EXAMPLE
        Test-IsElevated
    #>
    if (Get-Module -Name 'ActiveDirectory' -ListAvailable) {
        $true
    }
    else {
        $false
    }
}
function Invoke-Locksmith {
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

    .PARAMETER Scans
    Specify which scans you want to run. Available scans: 'All' or Auditing, ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC8, or 'PromptMe'

    -Scans All
    Run all scans (default)

    -Scans PromptMe
    Presents a grid view of the available scan types that can be selected and run them after you click OK.

    .PARAMETER OutputPath
    Specify the path where you want to save reports and mitigation scripts.

    .INPUTS
    None. You cannot pipe objects to Invoke-Locksmith.ps1.

    .OUTPUTS
    Output types:
    1. Console display of identified issues
    2. Console display of identified issues and their fixes
    3. CSV containing all identified issues
    4. CSV containing all identified issues and their fixes

    .NOTES
    Windows PowerShell cmdlet Restart-Service requires RunAsAdministrator
    #>

    [CmdletBinding()]
    param (
        [string]$Forest,
        [string]$InputPath,
        [int]$Mode = 0,
        [Parameter()]
        [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe')]
        [array]$Scans = 'All',
        [string]$OutputPath = (Get-Location).Path,
        [System.Management.Automation.PSCredential]$Credential
    )

    $Version = '2024.1'
    $LogoPart1 = @"
    _       _____  _______ _     _ _______ _______ _____ _______ _     _
    |      |     | |       |____/  |______ |  |  |   |      |    |_____|
    |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
"@
    $LogoPart2 = @"
        .--.                  .--.                  .--.
       /.-. '----------.     /.-. '----------.     /.-. '----------.
       \'-' .---'-''-'-'     \'-' .--'--''-'-'     \'-' .--'--'-''-'
        '--'                  '--'                  '--'
"@
    $VersionBanner = "                                                          v$Version"

    Write-Host $LogoPart1 -ForegroundColor Magenta
    Write-Host $LogoPart2 -ForegroundColor White
    Write-Host $VersionBanner -ForegroundColor Red

    # Check if ActiveDirectory PowerShell module is available, and attempt to install if not found
    $RSATInstalled = Test-IsRSATInstalled
    if ($RSATInstalled) {
        # Continue
    }
    else {
        Install-RSATADPowerShell
    }

    # Exit if running in restricted admin mode without explicit credentials
    if (!$Credential -and (Get-RestrictedAdminModeSetting)) {
        Write-Warning "Restricted Admin Mode appears to be in place, re-run with the '-Credential domain\user' option"
        break;
    }

    # Initial variables
    $AllDomainsCertPublishersSIDs = @()
    $AllDomainsDomainAdminSIDs = @()
    $ClientAuthEKUs = '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'
    $DangerousRights = 'GenericAll|WriteDacl|WriteOwner|WriteProperty'
    $EnrollmentAgentEKU = '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'
    $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
    $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
    $UnsafeOwners = 'S-1-1-0|-11$|-513$|-515$'
    $UnsafeUsers = 'S-1-1-0|-11$|-513$|-515$'

    # Generated variables
    $Dictionary = New-Dictionary
    $ForestGC = $(Get-ADDomainController -Discover -Service GlobalCatalog -ForceDiscover | Select-Object -ExpandProperty Hostname) + ":3268"
    $DNSRoot = [string]((Get-ADForest).RootDomain | Get-ADDomain).DNSRoot
    $EnterpriseAdminsSID = ([string]((Get-ADForest).RootDomain | Get-ADDomain).DomainSID) + '-519'
    $PreferredOwner = New-Object System.Security.Principal.SecurityIdentifier($EnterpriseAdminsSID)
    $DomainSIDs = (Get-ADForest).Domains | ForEach-Object { (Get-ADDomain $_).DomainSID.Value }
    $DomainSIDs | ForEach-Object {
        $AllDomainsCertPublishersSIDs += $_ + '-517'
        $AllDomainsDomainAdminSIDs += $_ + '-512'
    }

    # Add SIDs of (probably) Safe Users to $SafeUsers
    Get-ADGroupMember $EnterpriseAdminsSID | ForEach-Object {
        $SafeUsers += '|' + $_.SID.Value
    }

    (Get-ADForest).Domains | ForEach-Object {
        $DomainSID = (Get-ADDomain $_).DomainSID.Value
        $SafeGroupRIDs = @('-517', '-512')
        $SafeGroupSIDs = @('S-1-5-32-544')
        foreach ($rid in $SafeGroupRIDs ) {
            $SafeGroupSIDs += $DomainSID + $rid
        }
        foreach ($sid in $SafeGroupSIDs) {
            $users += (Get-ADGroupMember $sid -Server $_ -Recursive).SID.Value
        }
        foreach ($user in $users) {
            $SafeUsers += '|' + $user
        }
    }

    if ($Credential) {
        $Targets = Get-Target -Credential $Credential
    }
    else {
        $Targets = Get-Target
    }

    Write-Host "Gathering AD CS Objects from $($Targets)..."
    if ($Credential) {
        $ADCSObjects = Get-ADCSObject -Targets $Targets -Credential $Credential
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects -Credential $Credential
        $ADCSObjects += Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential
        $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential
        $CAHosts | ForEach-Object { $SafeUsers += '|' + $_.Name }
    }
    else {
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        Set-AdditionalCAProperty -ADCSObjects $ADCSObjects
        $ADCSObjects += Get-CAHostObject -ADCSObjects $ADCSObjects
        $CAHosts = Get-CAHostObject -ADCSObjects $ADCSObjects
        $CAHosts | ForEach-Object { $SafeUsers += '|' + $_.Name }
    }

    if ( $Scans ) {
        # If the Scans parameter was used, Invoke-Scans with the specified checks.
        $Results = Invoke-Scans -Scans $Scans
        # Re-hydrate the findings arrays from the Results hash table
        $AllIssues = $Results['AllIssues']
        $AuditingIssues = $Results['AuditingIssues']
        $ESC1 = $Results['ESC1']
        $ESC2 = $Results['ESC2']
        $ESC3 = $Results['ESC3']
        $ESC4 = $Results['ESC4']
        $ESC5 = $Results['ESC5']
        $ESC6 = $Results['ESC6']
        $ESC8 = $Results['ESC8']
    }

    # If these are all empty = no issues found, exit
    if ($null -eq $Results) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found.`n" -ForegroundColor Green
        Write-Host 'Thank you for using ' -NoNewline
        Write-Host "❤ Locksmith ❤ `n" -ForegroundColor Magenta
        break
    }

    switch ($Mode) {
        0 {
            Format-Result $AuditingIssues '0'
            Format-Result $ESC1 '0'
            Format-Result $ESC2 '0'
            Format-Result $ESC3 '0'
            Format-Result $ESC4 '0'
            Format-Result $ESC5 '0'
            Format-Result $ESC6 '0'
            Format-Result $ESC8 '0'
        }
        1 {
            Format-Result $AuditingIssues '1'
            Format-Result $ESC1 '1'
            Format-Result $ESC2 '1'
            Format-Result $ESC3 '1'
            Format-Result $ESC4 '1'
            Format-Result $ESC5 '1'
            Format-Result $ESC6 '1'
            Format-Result $ESC8 '1'
        }
        2 {
            $Output = 'ADCSIssues.CSV'
            Write-Host "Writing AD CS issues to $Output..."
            try {
                $AllIssues | Select-Object Forest, Technique, Name, Issue | Export-Csv -NoTypeInformation $Output
                Write-Host "$Output created successfully!`n"
            }
            catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        3 {
            $Output = 'ADCSRemediation.CSV'
            Write-Host "Writing AD CS issues to $Output..."
            try {
                $AllIssues | Select-Object Forest, Technique, Name, DistinguishedName, Issue, Fix | Export-Csv -NoTypeInformation $Output
                Write-Host "$Output created successfully!`n"
            }
            catch {
                Write-Host 'Ope! Something broke.'
            }
        }
        4 {
            Invoke-Remediation -AuditingIssues $AuditingIssues -ESC1 $ESC1 -ESC2 $ESC2 -ESC3 $ESC3 -ESC4 $ESC4 -ESC5 $ESC5 -ESC6 $ESC6
        }
    }
    Write-Host 'Thank you for using ' -NoNewline
    Write-Host "❤ Locksmith ❤`n" -ForegroundColor Magenta
}


Invoke-Locksmith -Mode $Mode -Scans $Scans
