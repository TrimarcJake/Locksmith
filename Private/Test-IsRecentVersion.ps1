function Test-IsRecentVersion {
    [CmdletBinding()]
    param (
        # Check a specific version number from the script
        [Parameter(Mandatory)]
            [string]$Version,
        # Define the number of days past a module release date at which to consider the release "out of date."
        [Parameter()]
            [int16]$Days = 60
    )

    try {
        # Checking the most recent release in GitHub, but we could also use PowerShell Gallery.
        $Uri = "https://api.github.com/repos/trimarcjake/locksmith/releases"
        $Releases = Invoke-RestMethod -Uri $uri -Method Get -DisableKeepAlive -ErrorAction Stop
        $LatestRelease = $Releases | Sort-Object -Property Published_At -Descending | Select-Object -First 1
        # Get the release date of the currently running version via the version parameter
        [datetime]$InstalledVersionReleaseDate = ($Releases | Where-Object {$_.tag_name -like "?$Version"}).published_at
        [datetime]$LatestReleaseDate    = $LatestRelease.published_at
        # $ModuleDownloadLink   = ( ($LatestRelease.Assets).Where({$_.Name -like "Locksmith-v*.zip"}) ).browser_download_url
        $ScriptDownloadLink   = ( ($LatestRelease.Assets).Where({$_.Name -eq 'Invoke-Locksmith.zip'}) ).browser_download_url

        $LatestReleaseInfo = @"
Locksmith Module Details:

Latest Version:`t`t $($LatestRelease.name)
Published at: `t`t $LatestReleaseDate
Install Module:`t`t Install-Module -Name Locksmith
Standalone Script:`t $ScriptDownloadLink
"@
    }
    catch {
        Write-Warning "Unable to find the latest available version of the Locksmith module on GitHub." -WarningAction Continue
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
    } elseif ( ($InstalledVersionDate) -and ($InstalledVersionReleaseDate -le $OutOfDateDate) ) {
        # If we found the installed version date and it is more than [x] days old
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        $IsRecentVersion = $false
    } else {
        # The installed version has not been found to be out of date.
        $IsRecentVersion = $True
    }

    # Return true/false
    $IsRecentVersion
}
