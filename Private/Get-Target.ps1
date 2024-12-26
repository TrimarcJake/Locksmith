function Get-Target {
    <#
    .SYNOPSIS
        Retrieves the target forest(s) based on a provided forest name, input file, or current Active Directory forest.

    .DESCRIPTION
        This script retrieves the target forest(s) based on the provided forest name, input file, or current Active Directory forest.
        If the $Forest parameter is specified, the script sets the target to the provided forest.
        If the $InputPath parameter is specified, the script reads the target forest(s) from the file specified by the input path.
        If neither $Forest nor $InputPath is specified, the script retrieves objects from the current Active Directory forest.
        If the $Credential parameter is specified, the script retrieves the target(s) using the provided credentials.

    .PARAMETER Forest
        Specifies a single forest to retrieve objects from.

    .PARAMETER InputPath
        Specifies the path to the file containing the target forest(s).

    .PARAMETER Credential
        Specifies the credentials to use for retrieving the target(s) from the Active Directory forest.

    .EXAMPLE
        Get-Target -Forest "example.com"
        Sets the target forest to "example.com".

    .EXAMPLE
        Get-Target -InputPath "C:\targets.txt"
        Retrieves the target forest(s) from the file located at "C:\targets.txt".

    .EXAMPLE
        Get-Target -Credential $cred
        Sets the target forest to the current Active Directory forest using the provided credentials.

    .OUTPUTS
        System.String
        The target(s) retrieved based on the specified parameters.

    #>

    param (
        [string]$Forest,
        [string]$InputPath,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Forest) {
        $Targets = $Forest
    } elseif ($InputPath) {
        $Targets = Get-Content $InputPath
    } else {
        if ($Credential) {
            $Targets = (Get-ADForest -Credential $Credential).Name
        } else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}
