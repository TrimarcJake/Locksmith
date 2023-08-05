function ConvertFrom-IdentityReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
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