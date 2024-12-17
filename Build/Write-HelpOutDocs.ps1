function Write-HelpOutDocs {
    <#
    .SYNOPSIS
    Write module documentation using the HelpOut module.

    .DESCRIPTION
    Writes module documentation using the HelpOut module. This functions generates the markdown and MAML help files from
    comment-based help in each of the functions. It will also create the external help cab file.

    .EXAMPLE
    Write-HelpOutDocs

    Does what it says on the tin.

    #>
    [CmdletBinding()]
    param ()

    $ModuleName = 'Locksmith'

    # Remove the module from the current session to ensure we are working with the current source version.
    Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue

    # Get the path to the module manifest. Check for either PSScriptRoot (if running from a script) or PWD (if running from the console).
    $ModulePath = if ($PSScriptRoot) {
        # If the $PSScriptRoot variable exists, check if you are in the build folder or the module folder.
        if ( (Split-Path -Path $PSScriptRoot -Leaf) -eq 'Build' ) {
            Split-Path -Path $PSScriptRoot -Parent
        } elseif ( (Split-Path -Path $PSScriptRoot -Leaf) -match $ModuleName ) {
            $PSScriptRoot
        } else {
            throw 'Failed to determine module manifest path. Please ensure you are in the module or build folder.'
        }
    } else {
        # If the $PSScriptRoot variable does not exist, check if you are in the build folder or the module folder.
        if ( (Split-Path -Path $PWD.Path -Leaf) -eq 'Build' ) {
            Split-Path -Path $PWD -Parent
        } elseif ( (Split-Path -Path $pwd -Leaf) -match $ModuleName ) {
            $PWD
        } else {
            throw 'Failed to determine module manifest path. Please ensure you are in the module or build folder.'
        }
    }

    # All of the above is fun, but is largely not needed if you just run the script file instead of pasting the code into the console.
    $ModuleManifestPath = Join-Path -Path $ModulePath -ChildPath "${ModuleName}.psd1"

    try {
        Import-Module ServerManager -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        Import-Module $ModuleManifestPath
    } catch {
        throw "Failed to import module manifest at $ModuleManifestPath. $_"
    }

    Save-MarkdownHelp -Module Locksmith -ExcludeFile @('CODE_OF_CONDUCT.md', 'CONTRIBUTING.md', 'TSS Specs.md')
    Save-MAML -Module Locksmith

    $params = @{
        CabFilesFolder  = "$PSScriptRoot\..\en-US"
        LandingPagePath = "$PSScriptRoot\..\docs\README.md"
        OutputFolder    = "$PSScriptRoot\..\en-US"
    }
    New-ExternalHelpCab @params

}

Write-HelpOutDocs
