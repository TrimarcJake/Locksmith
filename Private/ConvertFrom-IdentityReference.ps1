function ConvertFrom-IdentityReference {
    <#
    .SYNOPSIS
        Converts an identity reference to a security identifier (SID).

    .DESCRIPTION
        The ConvertFrom-IdentityReference function takes an identity reference as input and
        converts it to a security identifier (SID). It supports both SID strings and NTAccount objects.

    .PARAMETER Object
        Specifies the identity reference to be converted. This parameter is mandatory.

    .EXAMPLE
        $object = "S-1-5-21-3623811015-3361044348-30300820-1013"
        ConvertFrom-IdentityReference -Object $object
        # Returns "S-1-5-21-3623811015-3361044348-30300820-1013"

    .EXAMPLE
        $object = New-Object System.Security.Principal.NTAccount("DOMAIN\User")
        ConvertFrom-IdentityReference -Object $object
        # Returns "S-1-5-21-3623811015-3361044348-30300820-1013"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Object
    )

    $Principal = New-Object System.Security.Principal.NTAccount($Object)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    } else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    return $SID
}
