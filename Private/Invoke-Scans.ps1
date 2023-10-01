function Invoke-Scans {
    [CmdletBinding()]
    param (
    [Parameter()]
        [ValidateSet("Auditing","ESC1","ESC2","ESC3","ESC4","ESC5","ESC6","ESC8","All","PromptMe")]
        [array]$Scans = "All"
    )
    # Change PromptMe to its own parameter

    if ($Scans -eq $IsNullOrEmpty) {
        $Scans = 'All'
    }
    
    if ( $Scans -eq "PromptMe" ) {
        $GridViewTitle = "Select the tests to run and press Enter or click OK to continue..."

        # Check for Out-GridView or Out-ConsoleGridView
        if ((Get-Command Out-ConsoleGridView -ErrorAction SilentlyContinue) -and ($PSVersionTable.PSVersion.Major -ge 7)) {
            [string]$Scans = ($Dictionary | Select-Object Name,Type,Category | Out-ConsoleGridView -OutputMode Multiple -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            [string]$Scans = ($Dictionary | Select-Object Name,Type,Category | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
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
            Write-Host 'Identifying AD CS templates with dangerous configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
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
            Write-Host 'Identifying AD CS templates with dangerous configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
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

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC8

    # If these are all empty = no issues found, exit
    if ((!$AuditingIssues) -and (!$ESC1) -and (!$ESC2) -and (!$ESC3) -and (!$ESC4) -and (!$ESC5) -and (!$ESC6) -and (!$ESC8) ) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
        break
    }

    Return $AllIssues
}
