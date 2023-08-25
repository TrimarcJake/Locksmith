# Source: https://learn.microsoft.com/en-us/archive/blogs/janesays/compare-all-properties-of-two-objects-in-windows-powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$DN1,
    [Parameter(Mandatory=$true)]
    [string]$DN2
)

$ReferenceObject = Get-ADObject -Identity $DN1 -Properties *
$DifferenceObject = Get-ADObject -Identity $DN2 -Properties *

$ObjectProperties = $ReferenceObject | Get-Member -MemberType Property,NoteProperty | % Name
$ObjectProperties += $DifferenceObject | Get-Member -MemberType Property,NoteProperty | % Name
$ObjectProperties = $ObjectProperties | Sort | Select -Unique
$Differences = @()

foreach ($objectproperty in $ObjectProperties) {
    $difference = Compare-Object $ReferenceObject $DifferenceObject -Property $objectproperty
    if ($difference) {
        $differenceproperties = @{
            PropertyName = $objectproperty
            RefValue = ($difference | ? {$_.SideIndicator -eq '<='} | % $($objectproperty))
            DiffValue = ($difference | ? {$_.SideIndicator -eq '=>'} | % $($objectproperty))
        }
        $Differences += New-Object PSObject -Property $differenceproperties
    }
}
if ($Differences) {
    return (
        $Differences | Select PropertyName,RefValue,DiffValue
    )
}