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
            $Issue = [pscustomobject]@{
                Forest            = $_.CanonicalName.split('/')[0]
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Technique         = 'ESC8'
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
            [PSCustomObject]$Issue
        }
    }
}
