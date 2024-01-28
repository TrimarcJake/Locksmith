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
