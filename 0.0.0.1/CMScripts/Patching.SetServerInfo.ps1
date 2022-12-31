# SetServerInfo CM Script for Patching module
Param (

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $SourceHost,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $SourcePath,

    [Parameter()]
    [ValidateSet('String', 'Json')]
    [System.String]
    $OutputType = 'Json',

    [Parameter()]
    [ValidateSet('PatchWindow')]
    [System.String]
    $InfoType = 'PatchWindow',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $PatchWindowRegistryPath = 'REGISTRY::HKLM\SOFTWARE\ITAdmin',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $PatchWindowRegistryName = 'PatchWindow',

    [Parameter()]
    [ValidatePattern("^.*[^\r\n].*$")]
    [System.String]
    $NewInfo,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $LogPath = 'C:\_Admin'
)

if (!(Test-Path -Path $LogPath -ErrorAction SilentlyContinue)) {
    try {
        $null = New-Item -Path $LogPath -ItemType Directory
    }
    catch {
        if ($OutputType -eq 'String') {
            $output = "$env:COMPUTERNAME || Failed"
        }
        else {
            $output = [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Details      = 'FAILED'
            }
        }
        $output
        exit
    }
}

$LogPath = "$($LogPath)\Patching.SetServerInfo.log"
$logData = New-Object -TypeName System.Text.StringBuilder
$date = Get-Date

[void]$logData.AppendLine("$env:COMPUTERNAME || $($date.ToString('yyyy-MM-ddTHH:mm:ssL')) || InfoType: ${InfoType} || NewInfo: ${NewInfo} || Start")
[void]$logData.AppendLine("InfoStart::")

$obj = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Details = $null
}

Switch ($InfoType) {
    'PatchWindow' {
        if (-not(Test-Path -Path $PatchWindowRegistryPath)) {
            [void]$logData.AppendLine("RegistryPath: $PatchWindowRegistryPath")
            try {
                $null = New-Item -Path $PatchWindowRegistryPath
                [void]$logData.AppendLine("Registry Key Found")
            }
            catch {
                [void]$logData.AppendLine("Registry Key Not Found")
                $obj.Details = 'NO_KEY_EXISTS'
                break
            }
        }

        try {
            $obj.Details = (Set-ItemProperty -Path $PatchWindowRegistryPath -Name $PatchWindowRegistryName -Value $NewInfo -PassThru).$PatchWindowRegistryName
        }
        catch {
            [void]$logData.AppendLine("Registry Value Not Set")
            $obj.Details = 'NOT_SET'
            break
        }
    }
}

[void]$logData.AppendLine("::InfoEnd")
$logData.ToString() | Out-File -FilePath $LogPath -Append

if ($OutputType -eq 'String') {
    $output = New-Object -TypeName System.Text.StringBuilder
    [void]$output.Append("$env:COMPUTERNAME || $($obj.Details)")
    $output = $output.ToString()
}
else {
    $output = $obj
}
$output
