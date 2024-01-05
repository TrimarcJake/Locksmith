function Get-ModuleAge {
    [CmdletBinding()]
    param (
        # Check a specific version number from the script
        [Parameter()]
            [string]$Version,
        # Define the number of days past a module release date to consider the release "out of date."
        [Parameter()]
            [int16]$Days = 90
    )

    try {
        # Checking the most recent release in GitHub, but might want to switch to PowerShell Gallery.
        $Uri = "https://api.github.com/repos/trimarcjake/locksmith/releases"
        $Releases = Invoke-RestMethod -Uri $uri -Method Get -DisableKeepAlive -ErrorAction Stop
        $LatestRelease = $Releases | Sort-Object -Property Published_At -Descending | Select-Object -First 1

            $LatestReleaseDate = $LatestRelease.published_at
            $ModuleDownloadLink = ( ($LatestRelease.Assets).Where({$_.Name -like "Locksmith-v*.zip"}) ).browser_download_url
            $ScriptDownloadLink = ( ($LatestRelease.Assets).Where({$_.Name -eq 'Invoke-Locksmith.zip'}) ).browser_download_url
    }
    catch {
        #Check how old the installed Locksmith module is if unable to connect to the PowerShell Gallery or GitHub repository.
        $InstalledVersion = ((Get-Module Locksmith -ListAvailable).Version | Sort-Object -Descending | Select-Object -First 1).ToString()
        $InstalledVersionDate = [datetime]::Parse($InstalledVersion.Replace('.','-')+"-01")
    }
    finally {
        $OutOfDate = (Get-Date).Date.AddDays(-$Days)
        $Message = "Your currently installed version of Locksmith ($Version) is more than $Days days old. We recommend that you update to ensure the latest fixes are included."
        if ( (($LatestReleaseDate) -and $OutOfDate -ge $LatestReleaseDate) -or (($InstalledVersionDate) -and $OutOfDate -ge $InstalledVersionDate) ) {
            Write-Information -MessageData $Message -InformationAction Continue
        }
    }
}
