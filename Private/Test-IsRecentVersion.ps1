function Test-IsRecentVersion {
    <#
    .SYNOPSIS
        Check if the installed version of the Locksmith module is up to date.

    .DESCRIPTION
        This script checks the installed version of the Locksmith module against the latest release on GitHub.
        It determines if the installed version is considered "out of date" based on the number of days specified.
        If the installed version is out of date, a warning message is displayed along with information about the latest release.

    .PARAMETER Version
        Specifies the version number to check from the script.

    .PARAMETER Days
        Specifies the number of days past a module release date at which to consider the release "out of date".
        The default value is 60 days.

    .OUTPUTS
        System.Boolean
        Returns $true if the installed version is up to date, and $false if it is out of date.

    .EXAMPLE
        Test-IsRecentVersion -Version "2024.1" -Days 30
        True

        Test-IsRecentVersion -Version "2023.10" -Days 60
        WARNING: Your currently installed version of Locksmith (2.5) is more than 60 days old. We recommend that you update to ensure the latest findings are included.
        Locksmith Module Details:
        Latest Version:     2024.12.11
        Publishing Date:    01/28/2024 12:47:18
        Install Module:     Install-Module -Name Locksmith
        Standalone Script:  https://github.com/trimarcjake/locksmith/releases/download/v2.6/Invoke-Locksmith.zip
    #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        # Check a specific version number from the script
        [Parameter(Mandatory)]
        [string]$Version,
        # Define the number of days past a module release date at which to consider the release "out of date."
        [Parameter()]
        [int16]$Days = 60
    )

    # Strip the 'v' if it was used so the script can work with or without it in the input
    $Version = $Version.Replace('v', '')
    try {
        # Checking the most recent release in GitHub, but we could also use PowerShell Gallery.
        $Uri = "https://api.github.com/repos/trimarcjake/locksmith/releases"
        $Releases = Invoke-RestMethod -Uri $uri -Method Get -DisableKeepAlive -ErrorAction Stop
        $LatestRelease = $Releases | Sort-Object -Property Published_At -Descending | Select-Object -First 1
        # Get the release date of the currently running version via the version parameter
        [datetime]$InstalledVersionReleaseDate = ($Releases | Where-Object { $_.tag_name -like "?$Version" }).Published_at
        [datetime]$LatestReleaseDate = $LatestRelease.Published_at
        # $ModuleDownloadLink   = ( ($LatestRelease.Assets).Where({$_.Name -like "Locksmith-v*.zip"}) ).browser_download_url
        $ScriptDownloadLink = ( ($LatestRelease.Assets).Where({ $_.Name -eq 'Invoke-Locksmith.zip' }) ).browser_download_url

        $LatestReleaseInfo = @"
Locksmith Module Details:

Latest Version:`t`t $($LatestRelease.name)
Publishing Date: `t`t $LatestReleaseDate
Install Module:`t`t Install-Module -Name Locksmith
Standalone Script:`t $ScriptDownloadLink
"@
    } catch {
        Write-Warning "Unable to find the latest available version of the Locksmith module on GitHub." -WarningAction Continue
        # Find the approximate release date of the installed version. Handles version with or without 'v' prefix.
        $InstalledVersionMonth = [datetime]::Parse(($Version.Replace('v', '')).Replace('.', '-') + "-01")
        # Release date is typically the first Saturday of the month. Let's guess as close as possible!
        $InstalledVersionReleaseDate = $InstalledVersionMonth.AddDays( 6 - ($InstallVersionMonth.DayOfWeek) )
    }

    # The date at which to consider this module "out of date" is based on the $Days parameter
    $OutOfDateDate = (Get-Date).Date.AddDays(-$Days)
    $OutOfDateMessage = "Your currently installed version of Locksmith ($Version) is more than $Days days old. We recommend that you update to ensure the latest findings are included."

    # Compare the installed version release date to the latest release date
    if ( ($LatestReleaseDate) -and ($InstalledVersionReleaseDate -le ($LatestReleaseDate.AddDays(-$Days))) ) {
        # If we found the latest release date online and the installed version is more than [x] days older than it:
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        Write-Information -MessageData $LatestReleaseInfo -InformationAction Continue
        $IsRecentVersion = $false
    } elseif ( $InstalledVersionReleaseDate -le $OutOfDateDate ) {
        # If we didn't get the latest release date online, use the estimated release date to check age.
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        $IsRecentVersion = $false
    } else {
        # The installed version has not been found to be out of date.
        $IsRecentVersion = $True
    }

    # Return true/false
    $IsRecentVersion
}
