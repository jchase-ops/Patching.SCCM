# AutomaticRemediation CM Script for Patching module
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
    [ValidateSet('80070057', '80070070', '8024001E', '800F0986')]
    [System.String]
    $ErrorCode = '80070070',

    [Parameter()]
    [ValidatePattern("^\d{4}$")]
    [System.String]
    $SageSet = '1234',

    [Parameter()]
    [ValidateSet('RecycleBin', 'CCMCache', 'SoftwareDistribution', 'TEMP', 'All')]
    [System.String]
    $CleanupType = 'All',

    [Parameter()]
    [ValidateRange(1, 10)]
    [System.Int16]
    $RetryLimit = 5,

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

$LogPath = "$($LogPath)\Patching.AutomaticRemediation.log"
$logData = New-Object -TypeName System.Text.StringBuilder
$date = Get-Date

$cacheRegistryPath = 'REGISTRY::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
$cacheRegistryName = "StateFlags${SageSet}"
$cacheRegistryValue = 2
$cacheRegistryType = 'DWord'

$cleanupTypePaths = [ordered]@{
    RecycleBin           = "$($env:SystemDrive)\`$Recycle.Bin"
    CCMCache             = $env:UATDATA -Replace "(CCM)\\.*$", 'ccmcache'
    SoftwareDistribution = "$($env:SystemRoot)\SoftwareDistribution\Download"
    TEMP                 = $env:TEMP
}

[void]$logData.AppendLine("$env:COMPUTERNAME || $($date.ToString('yyyy-MM-ddTHH:mm:ssL')) || ErrorCode: $ErrorCode || SageSet: $SageSet || CleanupType: $CleanupType || RetryLimit: $RetryLimit || Start")
[void]$logData.AppendLine("InfoStart::")

$obj = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Details      = $null
}

$retryLimit = 5

Switch ($ErrorCode) {
    '80070057' {
        $retryCount = 0
        $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        do {
            [void]$logData.AppendLine("ErrorCode: ${ErrorCode} || RetryCount: ${retryCount} || RetryLimit: ${retryLimit}")
            $null = Invoke-WmiMethod -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList @(, $patches)
            $retryCount++
            Start-Sleep -Seconds 15
            $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        } until (($retryCount -eq $RetryLimit) -or (($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0)
        if ((($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0) {
            [void]$logData.AppendLine("RetryResult: Success")
            $obj.Details = 'SUCCESS'
        }
        else {
            [void]$logData.AppendLine("RetryResult: Failed")
            $obj.Details = 'FAILED'
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
    }
    '80070070' {
        $retryCount = 0
        $volumeCaches = Get-ChildItem -Path $cacheRegistryPath
        ForEach ($vc in $volumeCaches) {
            if ($cacheRegistryName -notin $($vc.GetValueNames())) {
                Push-Location -Path $cacheRegistryPath -StackName AutomaticRemediation
                Set-ItemProperty -Path $vc.PSChildName -Name $cacheRegistryName -Value $cacheRegistryValue -Type $cacheRegistryType
                Pop-Location -StackName AutomaticRemediation
                [void]$logData.AppendLine("ErrorCode: ${ErrorCode} || Cache: $($vc.PSChildName) || SageSet: ${SageSet}")
            }
        }
        Start-Process cleanmgr.exe -ArgumentList "/d C: /sagerun:${SageSet}" -Wait
        if ($?) {
            [void]$logData.AppendLine("DiskClean || Complete")
        }
        else {
            [void]$logData.AppendLine("DiskClean || Failed")
        }

        [void]$logData.AppendLine("CleanupType: $CleanupType || Start")
        if ($CleanupType -ne 'All') {
            Get-ChildItem -Path $cleanupTypePaths.GetValue($CleanupType) -Recurse | Remove-Item -Recurse -Force
        }
        else {
            ForEach ($key in $cleanupTypePaths.Keys) {
                Get-ChildItem -Path $cleanupTypePaths.GetValue($key) -Recurse | Remove-Item -Recurse -Force
            }
        }

        $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        do {
            [void]$logData.AppendLine("ErrorCode: ${ErrorCode} || RetryCount: ${retryCount} || RetryLimit: ${retryLimit}")
            $null = Invoke-WmiMethod -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList @(, $patches)
            $retryCount++
            Start-Sleep -Seconds 15
            $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        } until (($retryCount -eq $RetryLimit) -or (($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0)
        if ((($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0) {
            [void]$logData.AppendLine("RetryResult: Success")
            $obj.Details = 'SUCCESS'
        }
        else {
            [void]$logData.AppendLine("RetryResult: Failed")
            $obj.Details = 'FAILED'
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
    }
    '8024001E' {
        $retryCount = 0
        $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        do {
            [void]$logData.AppendLine("ErrorCode: ${ErrorCode} || RetryCount: ${retryCount} || RetryLimit: ${retryLimit}")
            $null = Invoke-WmiMethod -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList @(, $patches)
            $retryCount++
            Start-Sleep -Seconds 15
            $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        } until (($retryCount -eq $RetryLimit) -or (($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0)
        if ((($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0) {
            [void]$logData.AppendLine("RetryResult: Success")
            $obj.Details = 'SUCCESS'
        }
        else {
            [void]$logData.AppendLine("RetryResult: Failed")
            $obj.Details = 'FAILED'
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
    }
    '800F0986' {
        $retryCount = 0
        [void]$logData.AppendLine("ErrorCode: ${ErrorCode} || SFC || Start")
        Start-Process sfc.exe -ArgumentList '/scannow' -Wait
        if ($?) {
            [void]$logData.AppendLine("SFC || Complete")
        }
        else {
            [void]$logData.AppendLine("SFC || Failed")
        }
        $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        do {
            [void]$logData.AppendLine("ErrorCode: ${ErrorCode} || RetryCount: ${retryCount} || RetryLimit: ${retryLimit}")
            $null = Invoke-WmiMethod -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList @(, $patches)
            $retryCount++
            Start-Sleep -Seconds 15
            $patches = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate
        } until (($retryCount -eq $RetryLimit) -or (($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0)
        if ((($patches.ErrorCode | Sort-Object -Unique) -eq 0) -or @($patches).Count -eq 0) {
            [void]$logData.AppendLine("RetryResult: Success")
            $obj.Details = 'SUCCESS'
        }
        else {
            [void]$logData.AppendLine("RetryResult: Failed")
            $obj.Details = 'FAILED'
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
    }
}
$output
