function Get-Target {
    param (
        [string]$Forest,
        [string]$InputPath,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Forest) {
        $Targets = $Forest
    }
    elseif ($InputPath) {
        $Targets = Get-Content $InputPath
    } else {
        if ($Credential){
            $Targets = (Get-ADForest -Credential $Credential).Name
        } else {
            $Targets = (Get-ADForest).Name
        }
    }
    return $Targets
}