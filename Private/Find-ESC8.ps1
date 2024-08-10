function Find-ESC8 {
    <#
    .SYNOPSIS
        Finds ADCS objects with enrollment endpoints and identifies the enrollment type.

    .DESCRIPTION
        This script takes an array of ADCS objects and filters them based on the presence of a CA enrollment endpoint.
        It then determines the enrollment type (HTTP or HTTPS) for each object and returns the results.

    .PARAMETER ADCSObjects
        Specifies the array of ADCS objects to process. This parameter is mandatory.

    .OUTPUTS
        An object representing the ADCS object with the following properties:
        - Forest: The forest name of the object.
        - Name: The name of the object.
        - DistinguishedName: The distinguished name of the object.
        - CAEnrollmentEndpoint: The CA enrollment endpoint of the object.
        - Issue: The identified issue with the enrollment type.
        - Fix: The recommended fix for the issue.
        - Revert: The recommended revert action for the issue.
        - Technique: The technique used to identify the issue.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Results = $ADCSObjects | Find-ESC8
        $Results
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ADCSObjects
    )

    process {
        $ADCSObjects | Where-Object {
            $_.CAEnrollmentEndpoint
        } | ForEach-Object {
            foreach ($endpoint in $_.CAEnrollmentEndpoint) {
                $Issue = [pscustomobject]@{
                    Forest               = $_.CanonicalName.split('/')[0]
                    Name                 = $_.Name
                    DistinguishedName    = $_.DistinguishedName
                    CAEnrollmentEndpoint = $endpoint.URL
                    AuthType             = $endpoint.Auth
                    Issue                = 'An HTTP enrollment endpoint is available.'
                    Fix                  = @'
Disable HTTP access and enforce HTTPS.
Enable EPA.
Disable NTLM authentication (if possible.)
'@
                    Revert               = '[TODO]'
                    Technique            = 'ESC8'
                }
                if ($endpoint.URL -match '^https:') {
                    $Issue.Issue = 'An HTTPS enrollment endpoint is available.'
                    $Issue.Fix   = @'
Ensure EPA is enabled.
Disable NTLM authentication (if possible.)
'@
                }
                $Issue
            }
        }
    }
}
