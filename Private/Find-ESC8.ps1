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
                Forest               = $_.CanonicalName.split('/')[0]
                Name                 = $_.Name
                DistinguishedName    = $_.DistinguishedName
                CAEnrollmentEndpoint = $_.CAEnrollmentEndpoint
                Issue                = 'HTTP enrollment is enabled.'
                Fix                  = '[TODO]'
                Revert               = '[TODO]'
                Technique            = 'ESC8'
            }
            if ($_.CAEnrollmentEndpoint -like '^https*') {
                $Issue.Issue = 'HTTPS enrollment is enabled.'
            }
            $Issue
        }
    }
}
