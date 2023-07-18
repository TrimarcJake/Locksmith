.\Build\Build-Module.ps1
Import-Module .\Artefacts\Unpacked\Locksmith\Locksmith.psd1 -Force
Invoke-Locksmith

.\Build\Build-Module.ps1; Import-Module .\Artefacts\Unpacked\Locksmith\Locksmith.psd1 -Force; Invoke-Locksmith