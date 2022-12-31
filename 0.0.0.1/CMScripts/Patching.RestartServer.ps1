# RestartServer CMScript for Patching module
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
    [ValidateSet('PrepareCluster', 'RestartClusterServer', 'RebalanceCluster', 'Standard')]
    [System.String]
    $CommandType = 'Standard',

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

$date = Get-Date
$csvPath = "$($LogPath)\Patching.InitialClusterLayout_$($date.ToString('MMM')).csv"
$LogPath = "$($LogPath)\Patching.RestartServer.log"
$logData = New-Object -TypeName System.Text.StringBuilder

$evalHash = [ordered]@{
    0  = 'None'
    8  = 'PendingSoftReboot'
    9  = 'PendingHardReboot'
    10 = 'WaitReboot'
    12 = 'InstallComplete'
    14 = 'WaitServiceWindow'
    15 = 'WaitUserLogon'
    16 = 'WaitUserLogoff'
    17 = 'WaitJobUserLogon'
    18 = 'WaitUserReconnect'
    19 = 'PendingUserLogoff'
    20 = 'PendingUpdate'
    1  = 'Available'
    2  = 'Submitted'
    3  = 'Detecting'
    4  = 'PreDownload'
    5  = 'Downloading'
    6  = 'WaitInstall'
    7  = 'Installing'
    11 = 'Verifying'
    13 = 'Error'
    21 = 'WaitingRetry'
    22 = 'WaitPresModeOff'
}

if ($SourceHost -and $SourcePath) {
    $SourceHostPath = "\\$SourceHost\$SourcePath"
    if (Test-Path -Path "$SourceHostPath\ExcludedServers.txt" -ErrorAction SilentlyContinue) {
        $excludedServers = Get-Content -Path "$SourceHostPath\ExcludedServers.txt"
    }
}

[void]$logData.AppendLine("$env:COMPUTERNAME || $($date.ToString('yyyy-MM-ddTHH:mm:ssL')) || $CommandType || Start")
[void]$logData.AppendLine("InfoStart::")

$obj = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Details      = $null
}

Switch ($CommandType) {
    'PrepareCluster' {
        Get-ClusterGroup | Select-Object -Property Name, State, OwnerNode | Sort-Object -Property Name | Export-Csv -Path $csvPath -NoTypeInformation
        [void]$logData.AppendLine("${csvPath} Created")
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = 'PREPARED'
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
        exit
    }
    'RestartClusterServer' {
        if ($env:COMPUTERNAME -in $excludedServers) {
            [void]$logData.AppendLine("Excluded")
            [void]$logData.AppendLine("::InfoEnd")
            $obj.Details = 'EXCLUDED'
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
            exit
        }
        else {
            $details = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate | Select-Object -Property Name, ArticleID, EvaluationState, @{Label = 'ErrorCode'; Expression = { $_.ErrorCode.ToString('x').ToUpper() } }, PercentComplete
            if (@($details).Count -eq 0) {
                $details = @([PSCustomObject]@{ Name = 'None'; ArticleID = 'None'; EvaluationState = 'None'; ErrorCode = 'None'; PercentComplete = 'None' })
            }
            if (@($details | Where-Object { $_.EvaluationState -eq 13 }).Count -ge 1) {
                [void]$logData.AppendLine("ERROR")
                ForEach ($update in $($details | Where-Object { $_.EvaluationState -eq 13 })) {
                    [void]$logData.AppendLine("ArticleID: $($update.ArticleID) || EvaluationState: $($evalHash.Values.$($update.EvaluationState)) || ErrorCode: $($update.ErrorCode) || PercentComplete: $($update.PercentComplete.ToString())")
                }
                [void]$logData.AppendLine("::InfoEnd")
                $obj.Details = $details
                $logData.ToString() | Out-File -FilePath $LogPath -Append
                if ($OutputType -eq 'String') {
                    $output = New-Object -TypeName System.Text.StringBuilder
                    [void]$output.Append("$env:COMPUTERNAME || ")
                    ForEach ($update in $($details | Where-Object { $_.EvaluationState -eq 13 })) {
                        [void]$logData.AppendLine("ArticleID: $($update.ArticleID) - ErrorCode: $($update.ErrorCode) - ")
                    }
                    $output = $output.ToString().TrimEnd(' - ')
                }
                else {
                    $output = $obj
                }
                $output
                exit
            }
            elseif (@($details | Where-Object { $_.EvaluationState -in @(1, 2, 3, 4, 5, 6, 7, 11, 21, 22) }).Count -ge 1) {
                [void]$logData.AppendLine("BUSY")
                ForEach ($update in $($details | Where-Object { $_.EvaluationState -in @(1, 2, 3, 4, 5, 6, 7, 11, 21, 22) })) {
                    [void]$logData.AppendLine("ArticleID: $($update.ArticleID) || EvaluationState: $($evalHash.$($update.EvaluationState))")
                }
                [void]$logData.AppendLine("::InfoEnd")
                $obj.Details = $details
                $logData.ToString() | Out-File -FilePath $LogPath -Append
                if ($OutputType -eq 'String') {
                    $output = New-Object -TypeName System.Text.StringBuilder
                    [void]$output.Append("$env:COMPUTERNAME || ")
                    ForEach ($evalState in $($details | Where-Object { $_.EvaluationState -in @(1, 2, 3, 4, 5, 6, 7, 11, 21, 22) } | Select-Object -Property -ExpandProperty EvaluationState | Sort-Object -Unique)) {
                        [void]$output.Append("$($evalHash.$evalState): $(@($details | Where-Object { $_.EvaluationState -eq $evalState }).Count) - ")
                    }
                    $output = $output.ToString().TrimEnd(' - ')
                }
                else {
                    $output = $obj
                }
                $output
                exit
            }
            else {
                [void]$logData.AppendLine("READY")
                ForEach ($update in $details) {
                    [void]$logData.AppendLine("ArticleID: $($update.ArticleID) || EvaluationState: $($evalHash.$($update.EvaluationState))")
                }
                $otherClusterNodes = Get-ClusterNode | Select-Object -Property Id, Name, State | Where-Object { $_.Name -ne $env:COMPUTERNAME } | Sort-Object -Property Name Descending
                ForEach ($cg in $(Get-ClusterNode -Name $env:COMPUTERNAME | Get-ClusterGroup | Select-Object -Property Name, State, OwnerNode | Sort-Object -Property Name)) {
                    $moved = $false
                    [void]$logData.AppendLine("ClusterGroup: $($cg.Name) || OwnerNode: $($cg.OwnerNode) || State: $($cg.State) || Starting Move")
                    do {
                        ForEach ($node in $otherClusterNodes) {
                            $null = Move-ClusterGroup -Name $cg.Name -Node $node.Name -ErrorAction SilentlyContinue
                            if ($?) {
                                $moved = $true
                            }
                        }
                    } while ($moved -eq $false)
                    if ($(Get-ClusterGroup -Name $cg.Name).Status -notin @('Online', 'PartialOnline')) {
                        $null = Move-ClusterGroup -Name $cg.Name -Node $env:COMPUTERNAME -ErrorAction SilentlyContinue
                    }
                }
                if (@(Get-ClusterGroup | Where-Object { $_.Status -notin @('Online', 'PartialOnline') }).Count -gt 0) {
                    ForEach ($group in $(Get-ClusterGroup | Where-Object { $_.Status -notin @('Online', 'PartialOnline') })) {
                        $null = Move-ClusterGroup -Name $cg.Name -Node $env:COMPUTERNAME
                    }
                    [void]$logData.AppendLine("CLUSTER_GROUP_OFFLINE")
                    [void]$logData.AppendLine("::InfoEnd")
                    $obj.Details = 'CLUSTER_GROUP_OFFLINE'
                    $logData.ToString() | Out-File -FilePath $LogPath -Append
                    if ($OutputType -eq 'String') {
                        $output = New-Object -TypeName System.Text.StringBuilder
                        [void]$output.APpend("$env:COMPUTERNAME || CLUSTER_GROUP_OFFLINE")
                        $output = $output.ToString()
                    }
                    else {
                        $output = $obj
                    }
                    $output
                    exit
                }
                else {
                    if (@(Get-ClusterGroup | Where-Object { $_.OwnerNode -eq $env:COMPUTERNAME }).Count -ne 0) {
                        ForEach ($failedCG in $(Get-ClusterGroup | Where-Object { $_.OwnerNode -eq $env:COMPUTERNAME })) {
                            [void]$logData.AppendLine("ClusterGroup: $($failedCG.Name) || OwnerNode: $($failedCG.OwnerNode) || State: $($failedCG.State) || FAILED")
                        }
                        [void]$logData.AppendLine("CLUSTER_GROUP_MOVE_FAILED")
                        [void]$logData.AppendLine("::InfoEnd")
                        $obj.Details = 'CLUSTER_GROUP_MOVE_FAILED'
                        $logData.ToString() | Out-File -FilePath $LogPath -Append
                        if ($OutputType -eq 'String') {
                            $output = New-Object -TypeName System.Text.StringBuilder
                            [void]$output.Append("$env:COMPUTERNAME || CLUSTER_GROUP_MOVE_FAILED")
                            $output = $output.ToString()
                        }
                        else {
                            $output = $obj
                        }
                        $output
                        exit
                    }
                    else {
                        [void]$logData.AppendLine("REBOOTING")
                        [void]$logData.AppendLine("::InfoEnd")
                        $obj.Details = 'REBOOTING'
                        $logData.ToString() | Out-File -FilePath $LogPath -Append
                        if ($OutputType -eq 'String') {
                            $output = New-Object -TypeName System.Text.StringBuilder
                            [void]$output.Append("$env:COMPUTERNAME || REBOOTING")
                            $output = $output.ToString()
                        }
                        else {
                            $output = $obj
                        }
                        $output
                        Start-Sleep -Seconds 5
                        Restart-Computer -Force
                    }
                }
            }
        }
    }
    'RebalanceCluster' {
        $initialClusterLayout = Import-Csv -Path $csvPath
        if ($env:COMPUTERNAME -eq $(Get-ClusterNode | Sort-Object -Property Id | Select-Object -First 1).Name) {
            ForEach ($cg in $(Get-ClusterGroup)) {
                $init = $initialClusterLayout | Where-Object { $_.Name -eq $cg.Name }
                [void]$logData.AppendLine("ClusterGroup: $($cg.Name) || OwnerNode: $($cg.OwnerNode) || Expected: $($init.OwnerNode)")
                if ($cg.OwnerNode -ne $init.OwnerNode) {
                    try {
                        $null = Move-ClusterGroup -Name $cg.Name -Node $init.OwnerNode -ErrorAction Stop
                    }
                    catch {
                        [void]$logData.AppendLine("UNBALANCED")
                        [void]$logData.AppendLine("::InfoEnd")
                        $obj.Details = 'UNBALANCED'
                        $logData.ToString() | Out-File -FilePath $LogPath -Append
                        if ($OutputType -eq 'String') {
                            $output = New-Object -TypeName System.Text.StringBuilder
                            [void]$output.Append("$env:COMPUTERNAME || UNBALANCED")
                            $output = $output.ToString()
                        }
                        else {
                            $output = $obj
                        }
                        $output
                        exit
                    }
                }
            }
            [void]$logData.AppendLine("::InfoEnd")
            $obj.Details = 'REBALANCED'
            $logData.ToString() | Out-File -FilePath $LogPath -Append
            if ($OutputType -eq 'String') {
                $output = New-Object -TypeName System.Text.StringBuilder
                [void]$output.Append("$env:COMPUTERNAME || REBALANCED")
                $output = $output.ToString()
            }
            else {
                $output = $obj
            }
        }
        else {
            [void]$logData.AppendLine("SKIPPED")
            [void]$logData.AppendLine("::InfoEnd")
            $obj.Details = 'SKIPPED'
            $logData.ToString() | Out-File -FilePath $LogPath -Append
            if ($OutputType -eq 'String') {
                $output = New-Object -TypeName System.Text.StringBuilder
                [void]$output.Append("$env:COMPUTERNAME || SKIPPED")
                $output = $output.ToString()
            }
            else {
                $output = $obj
            }
        }
        $output
    }
    'Standard' {
        if ($env:COMPUTERNAME -in $excludedServers) {
            [void]$logData.AppendLine("Excluded")
            [void]$logData.AppendLine("::InfoEnd")
            $obj.Details = 'EXCLUDED'
            $logData.ToString() | Out-File -FilePath $LogPath -Append
            if ($OutputType -eq 'String') {
                $output = New-Object -TypeName System.Text.StringBuilder
                [void]$output.Append("$env:COMPUTERNAME || $($obj.Details)")
                $output = $output.ToString()
            }
            else {
                if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                    $output = [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        Details      = [System.Collections.Generic.List[System.Object]]::New()
                    }
                    ForEach ($d in $obj.Details) {
                        $output.Details.Add($([PSCustomObject]@{ KB = $d.ArticleID; ES = $d.EvaluationState; EC = $d.ErrorCode; PC = $d.PercentComplete }))
                    }
                    if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                        $output.Details = 'EXCEEDS'
                    }
                }
                else {
                    $output = $obj
                }
            }
            $output
            exit
        }
        else {
            $details = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate | Select-Object -Property Name, ArticleID, EvaluationState, @{Label = 'ErrorCode'; Expression = { $_.ErrorCode.ToString('x').ToUpper() } }, PercentComplete
            if (@($details).Count -eq 0) {
                $details = @([PSCustomObject]@{ Name = 'None'; ArticleID = 'None'; EvaluationState = 'None'; ErrorCode = 'None'; PercentComplete = 'None' })
                [void]$logData.AppendLine("ArticleID: None || EvaluationState: None || ErrorCode: None || PercentComplete: None")
                [void]$logData.AppendLine("REBOOTING")
                [void]$logData.AppendLine("::InfoEnd")
                $obj.Details = 'REBOOTING'
                $logData.ToString() | Out-File -FilePath $LogPath -Append
                if ($OutputType -eq 'String') {
                    $output = New-Object -TypeName System.Text.StringBuilder
                    [void]$output.Append("$env:COMPUTERNAME || REBOOTING")
                    $output = $output.ToString()
                }
                else {
                    $output = $obj
                }
                $output
                Start-Sleep -Seconds 5
                Restart-Computer -Force
            }
            else {
                if ($(@($details | Where-Object { $_.EvaluationState -eq 13 })).Count -ge 1) {
                    [void]$logData.AppendLine("ERROR")
                    ForEach ($update in $($details | Where-Object { $_.EvaluationState -eq 13 })) {
                        [void]$logData.AppendLine("ArticleID: $($update.ArticleID) || EvaluationState: $($evalHash.Values.$($update.EvaluationState)) || ErrorCode: $($update.ErrorCode) || PercentComplete: $($update.PercentComplete)")
                    }
                    [void]$logData.AppendLine("::InfoEnd")
                    $obj.Details = $details
                    $logData.ToString() | Out-File -FilePath $LogPath -Append
                    if ($OutputType -eq 'String') {
                        $output = New-Object -TypeName System.Text.StringBuilder
                        [void]$output.Append("$env:COMPUTERNAME || ")
                        ForEach ($update in $($details | Where-Object { $_.EvaluationState -eq 13 })) {
                            [void]$output.Append("ArticleID: $($update.ArticleID) - ErrorCode: $($update.ErrorCode) - ")
                        }
                        $output = $output.ToString().TrimEnd(' - ')
                    }
                    else {
                        if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                            $output = [PSCustomObject]@{
                                ComputerName = $env:COMPUTERNAME
                                Details      = [System.Collections.Generic.List[System.Object]]::New()
                            }
                            ForEach ($d in $obj.Details) {
                                $output.Details.Add($([PSCustomObject]@{ KB = $d.ArticleID; ES = $d.EvaluationState; EC = $d.ErrorCode; PC = $d.PercentComplete }))
                            }
                            if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                                $output.Details = 'EXCEEDS'
                            }
                        }
                        else {
                            $output = $obj
                        }
                    }
                    $output
                    exit
                }
                elseif ($(@($details | Where-Object { $_.EvaluationState -in @(1, 2, 3, 4, 5, 6, 7, 11, 21, 22) })).Count -ge 1) {
                    [void]$logData.AppendLine("BUSY")
                    ForEach ($update in $($details | Where-Object { $_.EvaluationState -in @(1, 2, 3, 4, 5, 6, 7, 11, 21, 22) })) {
                        [void]$logData.AppendLine("ArticleID: $($update.ArticleID) || EvaluationState: $($evalHash.Values.$($update.EvaluationState)) || ErrorCode: $($update.ErrorCode) || PercentComplete: $($update.PercentComplete)")
                    }
                    [void]$logData.AppendLine("::InfoEnd")
                    $obj.Details = $details
                    $logData.ToString() | Out-File -FilePath $LogPath -Append
                    if ($OutputType -eq 'String') {
                        $output = New-Object -TypeName System.Text.StringBuilder
                        [void]$output.Append("$env:COMPUTERNAME || ")
                        ForEach ($evalState in $($details | Where-Object { $_.EvaluationState -in @(1, 2, 3, 4, 5, 6, 7, 11, 21, 22) } | Select-Object -Property -ExpandProperty EvaluationState | Sort-Object -Unique)) {
                            [void]$output.Append("$($evalHash.Values.$evalState): $(($details | Where-Object { $_.EvaluationState -eq $evalState }).Count) - ")
                        }
                        $output = $output.ToString().TrimEnd(' - ')
                    }
                    else {
                        if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                            $output = [PSCustomObject]@{
                                ComputerName = $env:COMPUTERNAME
                                Details      = [System.Collections.Generic.List[System.Object]]::New()
                            }
                            ForEach ($d in $obj.Details) {
                                $output.Details.Add($([PSCustomObject]@{ KB = $d.ArticleID; ES = $d.EvaluationState; EC = $d.ErrorCode; PC = $d.PercentComplete }))
                            }
                            if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                                $output.Details = 'EXCEEDS'
                            }
                        }
                        else {
                            $output = $obj
                        }
                    }
                    $output
                    exit
                }
                else {
                    [void]$logData.AppendLine("REBOOTING")
                    [void]$logData.AppendLine("::InfoEnd")
                    $obj.Details = 'REBOOTING'
                    $logData.ToString() | Out-File -FilePath $LogPath -Append
                    if ($OutputType -eq 'String') {
                        $output = New-Object -TypeName System.Text.StringBuilder
                        [void]$output.Append("$env:COMPUTERNAME || REBOOTING")
                        $output = $output.ToString()
                    }
                    else {
                        $output = $obj
                    }
                    $output
                    Start-Sleep -Seconds 5
                    Restart-Computer -Force
                }
            }
        }
    }
}
