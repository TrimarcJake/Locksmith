function Export-RevertScript {
    <#
    .SYNOPSIS
        Creates a script that reverts the changes performed by Locksmith.

    .DESCRIPTION
        This script is used to revert changes performed by Locksmith.
        It takes in various arrays of objects representing auditing issues and ESC misconfigurations.
        It creates a new script called 'Invoke-RevertLocksmith.ps1' and adds the necessary commands
        to revert the changes made by Locksmith.

    .PARAMETER AuditingIssues
        An array of auditing issues to be reverted.

    .PARAMETER ESC1
        An array of ESC1 changes to be reverted.

    .PARAMETER ESC2
        An array of ESC2 changes to be reverted.

    .PARAMETER ESC3
        An array of ESC3 changes to be reverted.

    .PARAMETER ESC4
        An array of ESC4 changes to be reverted.

    .PARAMETER ESC5
        An array of ESC5 changes to be reverted.

    .PARAMETER ESC6
        An array of ESC6 changes to be reverted.

    .PARAMETER ESC11
        An array of ESC11 changes to be reverted.

    .PARAMETER ESC13
        An array of ESC13 changes to be reverted.

    .EXAMPLE
        $params = @{
            AuditingIssues = $AuditingIssues
            ESC1           = $ESC1
            ESC2           = $ESC2
            ESC3           = $ESC3
            ESC4           = $ESC4
            ESC5           = $ESC5
            ESC6           = $ESC6
            ESC11          = $ESC11
            ESC13          = $ESC13
        }
        Export-RevertScript @params
        Reverts the changes performed by Locksmith using the specified arrays of objects.
    #>

    [CmdletBinding()]
    param(
        [array]$AuditingIssues,
        [array]$ESC1,
        [array]$ESC2,
        [array]$ESC3,
        [array]$ESC4,
        [array]$ESC5,
        [array]$ESC6,
        [array]$ESC11,
        [array]$ESC13
    )
    begin {
        $Output = 'Invoke-RevertLocksmith.ps1'
        $RevertScript = [System.Text.StringBuilder]::New()
        [void]$RevertScript.Append("<#`nScript to revert changes performed by Locksmith`nCreated $(Get-Date)`n#>`n")
        $Objects = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC11 + $ESC13
    }
    process {
        if ($Objects) {
            $Objects | ForEach-Object {
                [void]$RevertScript.Append("$($_.Revert)`n")
            }
            $RevertScript.ToString() | Out-File -FilePath $Output
        }
    }
}
