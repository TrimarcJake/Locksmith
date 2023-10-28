param (
    [int]$Mode
)
function ConvertFrom-IdentityReference {
Export-ModuleMember -Function @($FunctionsToLoad) -Alias @($AliasesToLoad)

Invoke-Locksmith -Mode $Mode
