function Invoke-Scans {
    [CmdletBinding()]
    param (
    [Parameter()]
        [ValidateSet("Auditing","ESC1","ESC2","ESC3","ESC4","ESC5","ESC6","ESC8","All","PromptMe")]
        [array]$Scans = "All"
    )

    # Envision this array being created in the base Invoke-Locksmith function, but landing here for now:
    $EscalationPaths = @(
        [PSCustomObject]@{
            Name = 'ESC1'
            Description = 'Misconfigured Certificate Templates'
            FindFunction =  '[array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects'
            Fix = ''
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC1'
        },
        [PSCustomObject]@{
            Name = 'ESC2';
            Description = 'Misconfigured Certificate Templates'
            FindFunction =  'Find-ESC2'
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC2'
        },
        [PSCustomObject]@{
            Name = 'ESC3'
            Description = 'Enrollment Agent Templates'
            FindFunction =  'Find-ESC3'
            Fix = ''
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Enrollment%20Agent%20Templates%20%E2%80%94%20ESC3'
        }
        [PSCustomObject]@{ 
            Name = 'ESC4';
            Description = 'Vulnerable Certificate Template Access Control'
            FindFunction =  'Find-ESC4'
            Fix = ''
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Template%20Access%20Control%20%E2%80%94%20ESC4'
        },
        [PSCustomObject]@{
            Name = 'ESC5';
            Description = 'Vulnerable PKI Object Access Control'
            FindFunction =  'Find-ESC5'
            Fix = ''
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20PKI%20Object%20Access%20Control%20%E2%80%94%20ESC5'
        },
        [PSCustomObject]@{
            Name = 'ESC6'
            Description = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
            FindFunction =  'Find-ESC6'
            Fix = ''
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=EDITF_ATTRIBUTESUBJECTALTNAME2%20%E2%80%94%20ESC6'
        },
        [PSCustomObject]@{
            Name = 'ESC7'
            Description = 'Vulnerable Certificate Authority Access Control'
            FindFunction =  'Find-ESC7'
            Fix = ''
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Authority%20Access%20Control%20%E2%80%94%20ESC7'
        },
        [PSCustomObject]@{
            Name = 'ESC8'
            Description = 'NTLM Relay to AD CS HTTP Endpoints'
            FindFunction =  'Find-ESC8'
            Fix = ''
            Reference = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=NTLM%20Relay%20to%20AD%20CS%20HTTP%20Endpoints'
        },
        [PSCustomObject]@{
            Name = 'Auditing'
            Description = 'Gaps in auditing on certificate authorities and AD CS objects.'
            FindFunction =  'Find-AuditingIssue'
            Fix = ''
            Reference = ''
        }
    )
    
    if ($Scans -eq $IsNullOrEmpty) {
        $Scans = 'All'
    }
    
    if ( $Scans -eq "PromptMe" ) {
        $GridViewTitle = "Select the tests to run and press Enter or click OK to continue..."

        # Check for Out-GridView or Out-ConsoleGridView
        if ((Get-Command Out-ConsoleGridView -ErrorAction SilentlyContinue) -and ($PSVersionTable.PSVersion.Major -ge 7)) {
            $Scans = ($EscalationPaths | Select-Object Name,Description | Out-ConsoleGridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            $Scans = ($EscalationPaths | Select-Object Name,Description | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
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
            Write-Host 'Identifying AD CS templates with dangerous configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC2 {
            Write-Host 'Identifying AD CS templates with dangerous configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC3 {
            Write-Warning "Giddyup!"
        }
        ESC4 {
            Write-Host 'Identifying AD CS template and other objects with poor access control...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
        }
        ESC5 {
            Write-Host 'Identifying AD CS template and other objects with poor access control...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
        }
        ESC6 {
            Write-Host 'Identifying AD CS template and other objects with poor access control...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
        }
        ESC8 {
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
        All {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS template and other objects with poor access control...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
            Write-Host 'Identifying AD CS template and other objects with poor access control...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners
            Write-Host 'Identifying AD CS template and other objects with poor access control...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
    }

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC4 + $ESC5 + $ESC6 + $ESC8

    # If these are all empty = no issues found, exit
    if ((!$AuditingIssues) -and (!$ESC1) -and (!$ESC2) -and (!$ESC4) -and (!$ESC5) -and (!$ESC6) -and (!$ESC8) ) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
        break
    }

    Return $AllIssues
}
