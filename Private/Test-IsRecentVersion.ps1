function Test-IsRecentVersion {
    [CmdletBinding()]
    param (
        # Check a specific version number from the script
        [Parameter()]
            [string]$Version,
        # Define the number of days past a module release date at which to consider the release "out of date."
        [Parameter()]
            [int16]$Days = 90
    )

    if ( -not($Version) ) {
        # Try to get the installed version number if one is not passed to this function
        try {
            # Get the most recent version of the Locksmith module that is installed
            $Version = ((Get-Module Locksmith -ListAvailable).Version | Sort-Object -Descending | Select-Object -First 1).ToString()
            # Extrapolate the approximate release date of the installed version
            $InstalledVersionMonth = [datetime]::Parse($Version.Replace('.','-')+"-01")
            # Release date is typically the first Saturday of the month
            $InstalledVersionReleaseDate = $InstalledVersionMonth.AddDays( 6 - ($InstallVersionMonth.DayOfWeek) )
        } catch {
            Write-Error -Message "Unable to find an installed version of Locksmith. That's awkward."
            break
        }
    }

    try {
        # Checking the most recent release in GitHub, but might want to switch to PowerShell Gallery.
        $Uri = "https://api.github.com/repos/trimarcjake/locksmith/releases"
        $Releases = Invoke-RestMethod -Uri $uri -Method Get -DisableKeepAlive -ErrorAction Stop
        $LatestRelease = $Releases | Sort-Object -Property Published_At -Descending | Select-Object -First 1

            $LatestReleaseVersion = $LatestRelease.name -replace 'v',''
            [datetime]$LatestReleaseDate    = $LatestRelease.published_at
            # $ModuleDownloadLink   = ( ($LatestRelease.Assets).Where({$_.Name -like "Locksmith-v*.zip"}) ).browser_download_url
            $ScriptDownloadLink   = ( ($LatestRelease.Assets).Where({$_.Name -eq 'Invoke-Locksmith.zip'}) ).browser_download_url

            $LatestReleaseInfo = @"
Locksmith Module Details:

Latest Version:`t`t $LatestReleaseVersion
Latest Release:`t`t $LatestReleaseDate
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

    # If we found the latest release date online and the installed version is more than [x] days older than it:
    if ( ($LatestReleaseDate) -and $InstalledVersionReleaseDate -le ($LatestReleaseDate.AddDays(-$Days)) ) {
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        Write-Information -MessageData $LatestReleaseInfo -InformationAction Continue
        $IsRecentVersion = $false
    }
    # If we found the installed version date and it is more than [x] days old
    elseif ( ($InstalledVersionDate) -and $InstalledVersionReleaseDate -le $OutOfDateDate ) {
        Write-Warning -Verbose -Message $OutOfDateMessage -WarningAction Continue
        $IsRecentVersion = $false
    }
    else {
        # We could add positive checks, but they would be redundant...
        $IsRecentVersion = $True
    }

    $IsRecentVersion
}
