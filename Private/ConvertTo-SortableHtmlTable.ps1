function ConvertTo-SortableHtmlTable {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject[]]$InputObject
    )

    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
<style>
table {
  border-collapse: collapse;
  width: 100%;
}
th, td {
  text-align: left;
  padding: 8px;
}
tr:nth-child(even){background-color: #f2f2f2}
th {
  background-color: #4CAF50;
  color: white;
}
</style>
<script src='https://www.kryogenix.org/code/browser/sorttable/sorttable.js'></script>
</head>
<body>
"@

    $htmlFooter = @"
</body>
</html>
"@

    $htmlTable = $InputObject | ConvertTo-Html -Head $htmlHeader -PostContent $htmlFooter
    $htmlTable = $htmlTable -replace "<table>", "<table class='sortable'>"

    return $htmlTable
}