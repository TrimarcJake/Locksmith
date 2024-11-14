﻿param (
    # A CalVer string if you need to manually override the default yyyy.M.d version string.
    [string]$CalVer
)

if (Get-Module -Name 'PSPublishModule' -ListAvailable) {
    Write-Information 'PSPublishModule is installed.'
} else {
    Write-Information 'PSPublishModule is not installed. Attempting installation.'
    try {
        Install-Module -Name Pester -AllowClobber -Scope CurrentUser -SkipPublisherCheck -Force
        Install-Module -Name PSPublishModule -AllowClobber -Scope CurrentUser -Force
    }
    catch {
        Write-Error 'PSPublishModule installation failed.'
    }
}

Update-Module -Name PSPublishModule
Import-Module -Name PSPublishModule -Force

Build-Module -ModuleName 'Locksmith' {
    # Usual defaults as per standard module
    $Manifest = [ordered] @{
        ModuleVersion        = if ($Calver) {$CalVer} else {(Get-Date -Format yyyy.M.d)}
        CompatiblePSEditions = @('Desktop', 'Core')
        GUID                 = 'b1325b42-8dc4-4f17-aa1f-dcb5984ca14a'
        Author               = 'Jake Hildreth'
        Copyright            = "(c) 2022 - $((Get-Date).Year). All rights reserved."
        Description          = 'A small tool to find and fix common misconfigurations in Active Directory Certificate Services.'
        ProjectUri           = 'https://github.com/TrimarcJake/Locksmith'
        IconUri              = 'https://raw.githubusercontent.com/TrimarcJake/Locksmith/main/Images/locksmith.ico'
        PowerShellVersion    = '5.1'
        Tags                 = @('Windows', 'Locksmith', 'CA', 'PKI', 'ActiveDirectory', 'CertificateServices','ADCS')
    }
    New-ConfigurationManifest @Manifest

    # See [PR26](https://github.com/EvotecIT/PSPublishModule/pull/26) for notes about using placeholders and
    # built-in placeholders for common module metadata.
    # New-ConfigurationPlaceHolder -CustomReplacement @(
    #     @{ Find = '{CustomName}'; Replace = 'SpecialCase' }
    #     @{ Find = '{CustomVersion}'; Replace = '1.0.0' }
    # )

    # Add standard module dependencies (directly, but can be used with loop as well)
    #New-ConfigurationModule -Type RequiredModule -Name 'PSSharedGoods' -Guid 'Auto' -Version 'Latest'

    # Add external module dependencies, using loop for simplicity
    # those modules are not available in PowerShellGallery so user has to have them installed
    $ExternalModules = @(
        # Required RSAT AD module
        'ActiveDirectory'
        'ServerManager'
        # those modules are builtin in PowerShell so no need to install them
        # could as well be ignored with New-ConfigurationModuleSkip
        'Microsoft.PowerShell.Utility'
        'Microsoft.PowerShell.LocalAccounts'
        'Microsoft.PowerShell.Management'
        'Microsoft.PowerShell.Security'
        'CimCmdlets'
        'Dism'
    )
    foreach ($Module in $ExternalModules) {
        New-ConfigurationModule -Type ExternalModule -Name $Module
    }


    # Ignore missing modules or cmdlets during build process
    New-ConfigurationModuleSkip -IgnoreFunctionName @('Out-ConsoleGridView') -IgnoreModuleName @('Microsoft.PowerShell.ConsoleGuiTools')

    # Tells the script to exclude commands from functions if the module is not available to be loaded
    # New-ConfigurationCommand -CommandName @('') -ModuleName @('') # Populate arrays or remove empty example.

    $ConfigurationFormat = [ordered] @{
        RemoveComments                              = $false

        PlaceOpenBraceEnable                        = $true
        PlaceOpenBraceOnSameLine                    = $true
        PlaceOpenBraceNewLineAfter                  = $true
        PlaceOpenBraceIgnoreOneLineBlock            = $false

        PlaceCloseBraceEnable                       = $true
        PlaceCloseBraceNewLineAfter                 = $true
        PlaceCloseBraceIgnoreOneLineBlock           = $false
        PlaceCloseBraceNoEmptyLineBefore            = $true

        UseConsistentIndentationEnable              = $true
        UseConsistentIndentationKind                = 'space'
        UseConsistentIndentationPipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
        UseConsistentIndentationIndentationSize     = 4

        UseConsistentWhitespaceEnable               = $true
        UseConsistentWhitespaceCheckInnerBrace      = $true
        UseConsistentWhitespaceCheckOpenBrace       = $true
        UseConsistentWhitespaceCheckOpenParen       = $true
        UseConsistentWhitespaceCheckOperator        = $true
        UseConsistentWhitespaceCheckPipe            = $true
        UseConsistentWhitespaceCheckSeparator       = $true

        AlignAssignmentStatementEnable              = $true
        AlignAssignmentStatementCheckHashtable      = $true

        UseCorrectCasingEnable                      = $true
    }
    # format PSD1 and PSM1 files when merging into a single file
    # enable formatting is not required as Configuration is provided
    New-ConfigurationFormat -ApplyTo 'OnMergePSM1', 'OnMergePSD1' -Sort None @ConfigurationFormat
    # format PSD1 and PSM1 files within the module
    # enable formatting is required to make sure that formatting is applied (with default settings)
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'DefaultPSM1' -EnableFormatting -Sort None
    # when creating PSD1 use special style without comments and with only required parameters
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'OnMergePSD1' -PSD1Style 'Minimal'

    # configuration for documentation, at the same time it enables documentation processing
    New-ConfigurationDocumentation -Enable:$false -StartClean -UpdateWhenNew -PathReadme 'Docs\Readme.md' -Path 'Docs'

    New-ConfigurationImportModule -ImportSelf #-ImportRequiredModules

    New-ConfigurationBuild -Enable:$true -SignModule:$false -DeleteTargetModuleBeforeBuild -MergeModuleOnBuild -UseWildcardForFunctions

    $PreScriptMerge = {
        param (
            [int]$Mode,
            [Parameter()]
                [ValidateSet('Auditing','ESC1','ESC2','ESC3','ESC4','ESC5','ESC6','ESC8','All','PromptMe')]
                [array]$Scans = 'All'
        )
    }

    $PostScriptMerge = { Invoke-Locksmith -Mode $Mode -Scans $Scans }

    New-ConfigurationArtefact -Type Packed -Enable -Path "$PSScriptRoot\..\Artefacts\Packed" -ArtefactName '<ModuleName>.zip'
    New-ConfigurationArtefact -Type Script -Enable -Path "$PSScriptRoot\..\Artefacts\Script" -PreScriptMerge $PreScriptMerge -PostScriptMerge $PostScriptMerge -ScriptName "Invoke-<ModuleName>.ps1"
    New-ConfigurationArtefact -Type ScriptPacked -Enable -Path "$PSScriptRoot\..\Artefacts\ScriptPacked" -PreScriptMerge $PreScriptMerge -PostScriptMerge $PostScriptMerge -ScriptName 'Invoke-<ModuleName>.ps1' -ArtefactName 'Invoke-<ModuleName>.zip'
    # New-ConfigurationPublish -Type PowerShellGallery -FilePath 'C:\Users\jake.BLUETUXEDO\Documents\API Keys\PSGallery.txt'
}

Copy-Item "$PSScriptRoot\..\Artefacts\Script\Invoke-Locksmith.ps1" "$PSScriptRoot\..\"
