function Get-ColorBrightness {
    <#
    .SYNOPSIS
    Calculates the brightness of a given color in hexadecimal format.

    .DESCRIPTION
    The Get-ColorBrightness function takes a hexadecimal color code as input and calculates the 
    brightness of the color using the relative luminance formula. It then categorizes the brightness
    as "light" or "dark" based on a threshold value.

    .PARAMETER HexColor
    Specifies the hexadecimal color code to calculate the brightness for.

    .EXAMPLE
    Get-ColorBrightness -HexColor "#FF0000"
    Calculates the brightness of the color red (#FF0000) and returns "dark".

    .OUTPUTS
    System.String
    Returns a string value indicating whether the color is "light" or "dark" based on its brightness.

    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$HexColor
    )

    # Strip leading # from $HexColor if it exists
    if ($HexColor.StartsWith("#")) {
        $HexColor = $HexColor.Substring(1)
    }    

    # Convert hex color to RGB values
    $red = [convert]::ToInt32($HexColor.Substring(0, 2), 16)
    $green = [convert]::ToInt32($HexColor.Substring(2, 2), 16)
    $blue = [convert]::ToInt32($HexColor.Substring(4, 2), 16)

    # Calculate brightness using relative luminance formula
    $brightness = (0.2126 * $red + 0.7152 * $green + 0.0722 * $blue) / 255
    
    # Categorize brightness as "light" or "dark"
    if ($brightness -ge 0.5) {
        return "light"
    } else {
        return "dark"
    }
}