function Export-RevertScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$AuditingIssues,
        [Parameter(Mandatory = $false)]
        [array]$ESC1,
        [Parameter(Mandatory = $false)]
        [array]$ESC2,
        [Parameter(Mandatory = $false)]
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