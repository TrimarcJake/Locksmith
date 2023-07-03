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
            $Issue = New-Object -TypeName pscustomobject
            $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
            $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
            if ($_.CAEnrollmentEndpoint -like '^http*') {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value 'HTTP enrollment is enabled.' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name CAEnrollmentEndpoint -Value $_.CAEnrollmentEndpoint -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "TBD - Remediate by doing 1, 2, and 3" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value "TBD" -Force
            } else {
                $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value 'HTTPS enrollment is enabled.' -Force
                $Issue | Add-Member -MemberType NoteProperty -Name CAEnrollmentEndpoint -Value $_.CAEnrollmentEndpoint -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value "TBD - Remediate by doing 1, 2, and 3" -Force
                $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value "TBD" -Force
            }
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'ESC8'
            $Issue
        }
    }
}