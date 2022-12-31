# .ExternalHelp $PSScriptRoot\Receive-CMScriptInvocation-help.xml
function Receive-CMScriptInvocation {

    [CmdletBinding(DefaultParameterSetName = 'Initial')]

    Param (

        [Parameter(Mandatory, ParameterSetName = 'Refresh')]
        [Switch]
        $Refresh,

        [Parameter(ParameterSetName = 'Initial')]
        [Parameter(ParameterSetName = 'Refresh')]
        [Switch]
        $Quiet
    )

    $windowVisible = if ($(Get-Process -Id $([System.Diagnostics.Process]::GetCurrentProcess().Id)).MainWindowHandle -eq 0) { $false } else { $true }

    if ($PWD.Path -ne "$($script:Config.SiteCode):\") {
        Push-Location -Path "$($script:Config.SiteCode):\" -StackName $MyInvocation.MyCommand.ModuleName
    }

    $CurrentScripts = [System.Collections.Generic.List[System.Object]]($script:Config.RunningScripts | Where-Object { $_.ClientOperationID -notin @('2008', '2008R2', 'OFFLINE') })
    $ScriptName = $CurrentScripts.ScriptName | Sort-Object -Unique

    $RunspaceConfig = @{
        SiteCode = $script:Config.SiteCode
        ProviderMachineName = $script:Config.ProviderMachineName
        Domain = $script:Config.Domain
        Credential = $script:Config.Credential
    }

    $Sync = Initialize-RunspacePool -MaxRunSpaces $([int][math]::Ceiling($CurrentScripts.Count / 200))
    $runspaceLimit = [int][math]::Floor($CurrentScripts.Count / $Sync.Count)
    $runspaceRemainder = $CurrentScripts.Count % $Sync.Count
    $runspaceCount = 0
    $runspaceStart = 0
    if ($windowVisible -and !($Quiet)) {
        Write-Host "Creating Runspaces:" -NoNewline
    }

    Switch ($PSCmdlet.ParameterSetName) {
        'Initial' {
            do {
                if ($windowVisible -and !($Quiet)) {
                    Write-Host " $($runspaceCount + 1)" -ForegroundColor Green -NoNewline
                }
                if ($runspaceCount -eq 0) {
                    $runspaceModifier = $runspaceLimit + $runspaceRemainder - 1
                }
                else {
                    $runspaceModifier = $runspaceStart + $runspaceLimit - 1
                }
                $runspaceList = $CurrentScripts[$runspaceStart..$runspaceModifier]
                $runspaceStart = $runspaceStart + $runspaceLimit
                $scriptBlock = [System.Management.Automation.ScriptBlock] {
                    Param($RunspaceScripts, $Config, $RunspaceID)
                    Import-Module "$($env:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -Scope Global
                    $null = New-PSDrive -Name $Config.SiteCode -PSProvider CMSite -Root $Config.ProviderMachineName -Scope Global -Credential $Config.Credential
                    Set-Location "$($Config.SiteCode):\"
                    ForEach ($Setup in $RunspaceScripts) {
                        $tCount = 0
                        $task = Get-WmiObject -ComputerName $Config.ProviderMachineName -Namespace "root\sms\site_$($Config.SiteCode)" -ClassName SMS_ScriptsExecutionTask -Filter "clientOperationId='$($Setup.ClientOperationID)'" -Credential $Config.Credential
                        while (($task.CompletedClients -ne 1 -and $task.OverallScriptExecutionState -ne 1) -and $tCount -le 6) {
                            Start-Sleep -Seconds 5
                            $tCount++
                            $task = Get-WmiObject -ComputerName $Config.ProviderMachineName -Namespace "root\sms\site_$($Config.SiteCode)" -ClassName SMS_ScriptsExecutionTask -Filter "clientOperationId='$($Setup.ClientOperationId)'" -Credential $Config.Credential
                        }
                        $Setup.CompletedClients = $task.CompletedClients
                        $Setup.FailedClients = $task.FailedClients
                        $Setup.NotApplicableClients = $task.NotApplicableClients
                        $Setup.OfflineClients = $task.OfflineClients
                        $Setup.TotalClients = $task.TotalClients
                        $Setup.LastUpdateTime = $task.LastUpdateTime
                        $Setup.OverallScriptExecutionState = $task.OverallScriptExecutionState
                        $Setup.TaskID = $task.TaskID

                        $summary = Get-WmiObject -ComputerName $Config.ProviderMachineName -Namespace "root\sms\site_$($Config.SiteCode)" -ClassName SMS_ScriptsExecutionSummary -Filter "TaskId='$($task.TaskID)'" -Credential $Config.Credential
                        ForEach ($s in $summary) {
                            if ($null -ne $s.ScriptOutput) {
                                ForEach ($j in $($s.ScriptOutput | ConvertFrom-Json)) {
                                    $Setup.Details.Add($j)
                                }
                            }
                        }
                        $Sync.$RunspaceID.Completed++
                    }
                    $RunspaceScripts
                }
                $Sync."Runspace_${runspaceCount}".Total = $runspaceList.Count
                $runspaceParams = @{
                    RunspaceScripts = $runspaceList
                    Config = $RunspaceConfig
                    RunspaceID = "Runspace_${runspaceCount}"
                }
                Start-RunspaceJob -ID $($runspaceCount + 1) -ScriptBlock $scriptBlock -ParameterHash $runspaceParams
                $runspaceCount++
            } while ($runspaceCount -lt $Sync.Count)
            if ($windowVisible -and !($Quiet)) {
                $script:Config.RunningScripts = Receive-RunspaceJob -Activity "Receiving $ScriptName" | Sort-Object -Property ComputerName
            }
            else {
                $script:Config.RunningScripts = Receive-RunspaceJob -Quiet | Sort-Object -Property ComputerName
            }
        }
        'Refresh' {
            do {
                if ($windowVisible -and !($Quiet)) {
                    Write-Host " $($runspaceCount + 1)" -ForegroundColor Green -NoNewline
                }
                if ($runspaceCount -eq 0) {
                    $runspaceModifier = $runspaceLimit + $runspaceRemainder - 1
                }
                else {
                    $runspaceModifier = $runspaceStart + $runspaceLimit - 1
                }
                $runspaceList = $CurrentScripts[$runspaceStart..$runspaceModifier]
                $runspaceStart = $runspaceStart + $runspaceLimit
                $scriptBlock = [System.Management.Automation.ScriptBlock] {
                    Param($RunspaceScripts, $Config, $RunspaceID)
                    Import-Module "$($env:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -Scope Global
                    $null = New-PSDrive -Name $Config.SiteCode -PSProvider CMSite -Root $Config.ProviderMachineName -Scope Global -Credential $Config.Credential
                    Set-Location "$($Config.SiteCode):\"
                    ForEach ($Setup in $RunspaceScripts) {
                        $tCount = 0
                        $task = Get-WmiObject -ComputerName $Config.ProviderMachineName -Namespace "root\sms\site_$($Config.SiteCode)" -ClassName SMS_ScriptsExecutionTask -Filter "clientOperationId='$($Setup.ClientOperationID)'" -Credential $Config.Credential
                        while (($task.CompletedClients -ne 1 -and $task.OverallScriptExecutionState -ne 1) -and $tCount -le 6) {
                            Start-Sleep -Seconds 5
                            $tCount++
                            $task = Get-WmiObject -ComputerName $Config.ProviderMachineName -Namespace "root\sms\site_$($Config.SiteCode)" -ClassName SMS_ScriptsExecutionTask -Filter "clientOperationId='$($Setup.ClientOperationID)'" -Credential $Config.Credential
                        }
                        $Setup.CompletedClients = $task.CompletedClients
                        $Setup.FailedClients = $task.FailedClients
                        $Setup.NotApplicableClients = $task.NotApplicableClients
                        $Setup.OfflineClients = $task.OfflineClients
                        $Setup.TotalClients = $task.TotalClients
                        $Setup.LastUpdateTime = $task.LastUpdateTime
                        $Setup.OverallScriptExecutionState = $task.OverallScriptExecutionState
                        $Setup.Details = [System.Collections.Generic.List[System.Object]]::New()

                        $summary = Get-WmiObject -ComputerName $Config.ProviderMachineName -Namespace "root\sms\site_$($Config.SiteCode)" -ClassName SMS_ScriptsExecutionSummary -Filter "TaskId='$($task.TaskID)'" -Credential $Config.Credential
                        ForEach ($s in $summary) {
                            if ($null -ne $s.ScriptOutput) {
                                ForEach ($j in $($s.ScriptOutput | ConvertFrom-Json)) {
                                    $Setup.Details.Add($j)
                                }
                            }
                        }
                        $Sync.$RunspaceID.Completed++
                    }
                    $RunspaceScripts
                }
                $Sync."Runspace_${runspaceCount}".Total = $runspaceList.Count
                $runspaceParams = @{
                    RunspaceScripts = $runspaceList
                    Config = $RunspaceConfig
                    RunspaceID = "Runspace_${runspaceCount}"
                }
                Start-RunspaceJob -ID $($runspaceCount + 1) -ScriptBlock $scriptBlock -ParameterHash $runspaceParams
                $runspaceCount++
            } while ($runspaceCount -lt $Sync.Count)
            if ($windowVisible -and !($Quiet)) {
                $script:Config.RunningScripts = Receive-RunspaceJob -Activity "Receiving $ScriptName" | Sort-Object -Property ComputerName
            }
            else {
                $script:Config.RunningScripts = Receive-RunspaceJob -Quiet | Sort-Object -Property ComputerName
            }
        }
    }

    if (Get-Location -StackName $MyInvocation.MyCommand.ModuleName -ErrorAction SilentlyContinue) {
        Pop-Location -StackName $MyInvocation.MyCommand.ModuleName
    }

    $script:Config.RunningScripts
}
