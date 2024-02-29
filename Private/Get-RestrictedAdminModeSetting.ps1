function Get-RestrictedAdminModeSetting {
    <#
    .SYNOPSIS
        Retrieves the current configuration of the Restricted Admin Mode setting.

    .DESCRIPTION
        This script retrieves the current configuration of the Restricted Admin Mode setting from the registry. 
        It checks if the DisableRestrictedAdmin value is set to '0' and the DisableRestrictedAdminOutboundCreds value is set to '1'.
        If both conditions are met, it returns $true; otherwise, it returns $false.

    .PARAMETER None

    .EXAMPLE
        Get-RestrictedAdminModeSetting
        True
    #>

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
