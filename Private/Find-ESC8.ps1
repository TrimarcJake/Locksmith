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
            $Issue = [ordered] @{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
            }
            if ($_.CAEnrollmentEndpoint -like '^http*') {
                $Issue['Issue'] = 'HTTP enrollment is enabled.'
                $Issue['CAEnrollmentEndpoint'] = $_.CAEnrollmentEndpoint
                $Issue['Fix'] = 'TBD - Remediate by doing 1, 2, and 3'
                $Issue['Revert'] = 'TBD'
            } else {
                $Issue['Issue'] = 'HTTPS enrollment is enabled.'
                $Issue['CAEnrollmentEndpoint'] = $_.CAEnrollmentEndpoint
                $Issue['Fix'] = 'TBD - Remediate by doing 1, 2, and 3'
                $Issue['Revert'] = 'TBD'
            }
            $Issue['Technique'] = 'ESC8'
            $Severity = Set-Severity -Issue $Issue
            $Issue['Severity'] = $Severity
            [PSCustomObject] $Issue
        }
    }
}