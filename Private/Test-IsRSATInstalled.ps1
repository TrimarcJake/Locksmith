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
    } else {
        $false
    }
}