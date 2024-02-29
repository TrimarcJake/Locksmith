function New-OutputPath {
    <#
    .SYNOPSIS
        Creates output directories for each forest.

    .DESCRIPTION
        This script creates one output directory per forest specified in the $Targets variable.
        The output directories are created under the $OutputPath directory.

    .PARAMETER Targets
        Specifies the forests for which output directories need to be created.

    .PARAMETER OutputPath
        Specifies the base path where the output directories will be created.

    .EXAMPLE
        New-OutputPath -Targets "Forest1", "Forest2" -OutputPath "C:\Output"
        This example creates two output directories named "Forest1" and "Forest2" under the "C:\Output" directory.

    #>

    [CmdletBinding(SupportsShouldProcess)]
    param ()
    # Create one output directory per forest
    foreach ( $forest in $Targets ) {
        $ForestPath = $OutputPath + "`\" + $forest
        New-Item -Path $ForestPath -ItemType Directory -Force  | Out-Null
    }
}
