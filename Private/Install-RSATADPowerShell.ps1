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
            Write-Host "No: " -NoNewLine
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Server OSes, works with Windows Server 2012 R2 through Windows Server 2022
                    Install-WindowsFeature -Name RSAT-AD-PowerShell
                } catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            } else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        } else {
            Write-Warning "The Active Directory PowerShell module is not installed."
            Write-Host "If you continue, Locksmith will attempt to install the Active Directory PowerShell module for you.`n" -ForegroundColor Yellow
            Write-Host "`nCOMMAND: Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online`n" -ForegroundColor Cyan
            Write-Host "Continue with this operation? [Y] Yes " -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: " -NoNewLine
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                try {
                    Write-Host "Beginning the ActiveDirectory PowerShell module installation, please wait.."
                    # Attempt to install ActiveDirectory PowerShell module for Windows Desktop OSes
                    Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
                } catch {
                    Write-Error 'Could not install ActiveDirectory PowerShell module. This module needs to be installed to run Locksmith successfully.'
                }
            } else {
                Write-Host "ActiveDirectory PowerShell module NOT installed. Please install to run Locksmith successfully.`n" -ForegroundColor Yellow
                break;
            }
        }
    } else {
        Write-Warning -Message "The ActiveDirectory PowerShell module is required for Locksmith, but is not installed. Please launch an elevated PowerShell session to have this module installed for you automatically."
        # The goal here is to exit the script without closing the PowerShell window. Need to test.
        Return
    }
}