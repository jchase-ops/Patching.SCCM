# GetServerInfo CMScript for Patching module
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
    [ValidateSet('Cluster', 'DefaultService', 'DesktopExperience', 'DriveSpace', 'IIS', 'InstalledPatches', 'PatchingStatus', 'PatchWindow', 'Service', 'Task', 'Win32Class')]
    [System.String]
    $InfoType = 'DriveSpace',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $Name,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $RegistryPath = 'REGISTRY::HKLM\SOFTWARE\ITAdmin',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $RegistryName = 'PatchWindow',

    [Parameter()]
    [ValidateSet('BaseBoard', 'BIOS', 'ComputerSystem', 'ComputerSystemProduct', 'DiskDrive', 'DiskPartition', 'LogicalDisk', 'NetworkAdapter', 'OperatingSystem', 'OptionalFeature', 'PhysicalMemory', 'Process', 'Processor')]
    [System.String]
    $Win32Class,

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
                Details      = 'Failed'
            }
        }
        $output
        exit
    }
}

$LogPath = "$($LogPath)\Patching.GetServerInfo.log"
$logData = New-Object -TypeName System.Text.StringBuilder
$date = Get-Date

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
$serviceStatusHash = [ordered]@{
    Stopped         = 1
    StartPending    = 2
    StopPending     = 3
    Running         = 4
    ContinuePending = 5
    PausePending    = 6
    Paused          = 7
}
$taskStateHash = [ordered]@{
    Unknown  = 0
    Disabled = 1
    Queued   = 2
    Ready    = 3
    Running  = 4
}
$patchDescriptionHash = [ordered]@{
    'Hotfix'          = '0'
    'Security Update' = '1'
    'Update'          = '2'
}
$defaultServiceList = [ordered]@{
    AJRouter                                   = '0'
    ALG                                        = '1'
    AppIDSvc                                   = '2'
    Appinfo                                    = '3'
    AppMgmt                                    = '4'
    AppReadiness                               = '5'
    AppVClient                                 = '6'
    AppXSvc                                    = '7'
    AudioEndpointBuilder                       = '8'
    Audiosrv                                   = '9'
    AxInstSV                                   = '10'
    BFE                                        = '11'
    BITS                                       = '12'
    BrokerInfrastructure                       = '13'
    Browser                                    = '14'
    bthserv                                    = '15'
    CDPSvc                                     = '16'
    CDPUserSvc                                 = '17'
    CertPropSvc                                = '18'
    ClipSVC                                    = '19'
    COMSysApp                                  = '20'
    CoreMessagingRegistrar                     = '21'
    CryptSvc                                   = '22'
    CscService                                 = '23'
    DcomLaunch                                 = '24'
    DcpSvc                                     = '25'
    defragsvc                                  = '26'
    DeviceAssociationService                   = '27'
    DeviceInstall                              = '28'
    DevQueryBroker                             = '29'
    Dhcp                                       = '30'
    'diagnosticshub.standardcollector.service' = '31'
    DiagTrack                                  = '32'
    DmEnrollmentSvc                            = '33'
    dmwappushservice                           = '34'
    Dnscache                                   = '35'
    dot3svc                                    = '36'
    DPS                                        = '37'
    DsmSvc                                     = '38'
    DsSvc                                      = '39'
    EapHost                                    = '40'
    EFS                                        = '41'
    embeddedmode                               = '42'
    EntAppSvc                                  = '43'
    EventLog                                   = '44'
    EventSystem                                = '45'
    fdPHost                                    = '46'
    FDResPub                                   = '47'
    FontCache                                  = '48'
    FrameServer                                = '49'
    gpsvc                                      = '50'
    hidserv                                    = '51'
    HvHost                                     = '52'
    icssvc                                     = '53'
    IKEEXT                                     = '54'
    Imhosts                                    = '55'
    iphlpsvc                                   = '56'
    KeyIso                                     = '57'
    KPSSVC                                     = '58'
    KtmRm                                      = '59'
    LanmanServer                               = '60'
    LanmanWorkstation                          = '61'
    lfsvc                                      = '62'
    LicenseManager                             = '63'
    lltdsvc                                    = '64'
    LSM                                        = '65'
    MapsBroker                                 = '66'
    MpsSvc                                     = '67'
    MSDTC                                      = '68'
    MSiSCSI                                    = '69'
    msiserver                                  = '70'
    NcaSvc                                     = '71'
    NcbService                                 = '72'
    Netlogon                                   = '73'
    Netman                                     = '74'
    netprofm                                   = '75'
    NetSetupSvc                                = '76'
    NetTcpPortSharing                          = '77'
    NgcCtnrSvc                                 = '78'
    NgcSvc                                     = '79'
    NlaSvc                                     = '80'
    nsi                                        = '81'
    OneSyncSvc                                 = '82'
    PcaSvc                                     = '83'
    PerfHost                                   = '84'
    PhoneSvc                                   = '85'
    PimIndexMaintenanceSvc                     = '86'
    pla                                        = '87'
    PlugPlay                                   = '88'
    PolicyAgent                                = '89'
    Power                                      = '90'
    PrintNotify                                = '91'
    ProfSvc                                    = '92'
    QWAVE                                      = '93'
    RasAuto                                    = '94'
    RasMan                                     = '95'
    RemoteAccess                               = '96'
    RemoteRegistry                             = '97'
    RmSvc                                      = '98'
    RpcEptMapper                               = '99'
    RpcLocator                                 = '100'
    RpcSs                                      = '101'
    RSoPProv                                   = '102'
    sacsvr                                     = '103'
    SamSs                                      = '104'
    SCardSvr                                   = '105'
    ScDeviceEnum                               = '106'
    Schedule                                   = '107'
    SCPolicySvc                                = '108'
    seclogon                                   = '109'
    SENS                                       = '110'
    SensorDataService                          = '111'
    SensorService                              = '112'
    SensrSvc                                   = '113'
    SessionEnv                                 = '114'
    SharedAccess                               = '115'
    ShellHWDetection                           = '116'
    smphost                                    = '117'
    SNMPTRAP                                   = '118'
    Spooler                                    = '119'
    sppsvc                                     = '120'
    SSDPSRV                                    = '121'
    SstpSvc                                    = '122'
    StateRepository                            = '123'
    stisvc                                     = '124'
    StorSvc                                    = '125'
    svsvc                                      = '126'
    swprv                                      = '127'
    SysMain                                    = '128'
    SystemEventsBroker                         = '129'
    TabletInputService                         = '130'
    TapiSrv                                    = '131'
    TermService                                = '132'
    Themes                                     = '133'
    TieringEngineService                       = '134'
    tiledatamodelsvc                           = '135'
    TimeBrokerSvc                              = '136'
    TrkWks                                     = '137'
    TrustedInstaller                           = '138'
    tzautoupdate                               = '139'
    UALSVC                                     = '140'
    UevAgentService                            = '141'
    UIODetect                                  = '142'
    UmRdpService                               = '143'
    UnistoreSvc                                = '144'
    upnphost                                   = '145'
    UserDataSvc                                = '146'
    UserManager                                = '147'
    UsoSvc                                     = '148'
    VaultSvc                                   = '149'
    vds                                        = '150'
    vmicguestinterface                         = '151'
    vmicheartbeat                              = '152'
    vmickvpexchange                            = '153'
    vmicrdv                                    = '154'
    vmicshutdown                               = '155'
    vmictimesync                               = '156'
    vmicvmsession                              = '157'
    vmicvss                                    = '158'
    VSS                                        = '159'
    W32Time                                    = '160'
    WalletService                              = '161'
    WbioSrvc                                   = '162'
    Wcmsvc                                     = '163'
    WdiServiceHost                             = '164'
    WdiSystemHost                              = '165'
    WdNisSvc                                   = '166'
    Wecsvc                                     = '167'
    WEPHOSTSVC                                 = '168'
    wercplsupport                              = '169'
    WerSvc                                     = '170'
    WiaRpc                                     = '171'
    WinDefend                                  = '172'
    WinHttpAutoProxySvc                        = '173'
    Winmgmt                                    = '174'
    WinRM                                      = '175'
    wisvc                                      = '176'
    wlidsvc                                    = '177'
    wmiApSrv                                   = '178'
    WPDBusEnum                                 = '179'
    WpnService                                 = '180'
    WpnUserService                             = '181'
    WSearch                                    = '182'
    wuauserv                                   = '183'
    wudfsvc                                    = '184'
    XblAuthManager                             = '185'
    XblGameSave                                = '186'
}
$optionalFeatureHash = [ordered]@{
    'ActiveDirectory-PowerShell'                                  = 0
    'ADCertificateServicesRole'                                   = 1
    'AuthManager'                                                 = 2
    'BitLocker'                                                   = 3
    'Bitlocker-Utilities'                                         = 4
    'BITS'                                                        = 5
    'BITSExtensions-Upload'                                       = 6
    'CCFFilter'                                                   = 7
    'CertificateEnrollmentPolicyServer'                           = 8
    'CertificateEnrollmentServer'                                 = 9
    'CertificateServices'                                         = 10
    'ClientForNFS-Infrastructure'                                 = 11
    'Containers'                                                  = 12
    'CoreFileServer'                                              = 13
    'DataCenterBridging'                                          = 14
    'DataCenterBridging-LLDP-Tools'                               = 15
    'Dedup-Core'                                                  = 16
    'DeviceHealthAttestationService'                              = 17
    'DFSN-Server'                                                 = 18
    'DFSR-Infrastructure-ServerEdition'                           = 19
    'DHCPServer'                                                  = 20
    'DHCPServer-Tools'                                            = 21
    'DirectoryServices-ADAM'                                      = 22
    'DirectoryServices-ADAM-Tools'                                = 23
    'DirectoryServices-AdministrativeCenter'                      = 24
    'DirectoryServices-DomainController'                          = 25
    'DirectoryServices-DomainController-Tools'                    = 26
    'DiskIo-QoS'                                                  = 27
    'DNS-Server-Full-Role'                                        = 28
    'DNS-Server-Tools'                                            = 29
    'DSC-Service'                                                 = 30
    'EnhancedStorage'                                             = 31
    'FabricShieldedTools'                                         = 32
    'FailoverCluster-AdminPak'                                    = 33
    'FailoverCluster-AutomationServer'                            = 34
    'FailoverCluster-CmdInterface'                                = 35
    'FailoverCluster-FullServer'                                  = 36
    'FailoverCluster-PowerShell'                                  = 37
    'FileAndStorage-Services'                                     = 38
    'FileServerVSSAgent'                                          = 39
    'File-Services'                                               = 40
    'FRS-Infrastructure'                                          = 41
    'FSRM-Infrastructure'                                         = 42
    'FSRM-Infrastructure-Services'                                = 43
    'HardenedFabricEncryptionTask'                                = 44
    'HostGuardianService-Package'                                 = 45
    'IdentityServer-SecurityTokenService'                         = 46
    'IIS-ApplicationDevelopment'                                  = 47
    'IIS-ApplicationInit'                                         = 48
    'IIS-ASP'                                                     = 49
    'IIS-ASPNET'                                                  = 50
    'IIS-ASPNET45'                                                = 51
    'IIS-BasicAuthentication'                                     = 52
    'IIS-CertProvider'                                            = 53
    'IIS-CGI'                                                     = 54
    'IIS-ClientCertificateMappingAuthentication'                  = 55
    'IIS-CommonHttpFeatures'                                      = 56
    'IIS-CustomLogging'                                           = 57
    'IIS-DefaultDocument'                                         = 58
    'IIS-DigestAuthentication'                                    = 59
    'IIS-DirectoryBrowsing'                                       = 60
    'IIS-FTPExtensibility'                                        = 61
    'IIS-FTPServer'                                               = 62
    'IIS-FTPSvc'                                                  = 63
    'IIS-HealthAndDiagnostics'                                    = 64
    'IIS-HostableWebCore'                                         = 65
    'IIS-HttpCompressionDynamic'                                  = 66
    'IIS-HttpCompressionStatic'                                   = 67
    'IIS-HttpErrors'                                              = 68
    'IIS-HttpLogging'                                             = 69
    'IIS-HttpRedirect'                                            = 70
    'IIS-HttpTracing'                                             = 71
    'IIS-IIS6ManagementCompatibility'                             = 72
    'IIS-IISCertificateMappingAuthentication'                     = 73
    'IIS-IPSecurity'                                              = 74
    'IIS-ISAPIExtensions'                                         = 75
    'IIS-ISAPIFilter'                                             = 76
    'IIS-LegacyScripts'                                           = 77
    'IIS-LegacySnapIn'                                            = 78
    'IIS-LoggingLibraries'                                        = 79
    'IIS-ManagementConsole'                                       = 80
    'IIS-ManagementScriptingTools'                                = 81
    'IIS-ManagementService'                                       = 82
    'IIS-Metabase'                                                = 83
    'IIS-NetFxExtensibility'                                      = 84
    'IIS-NetFxExtensibility45'                                    = 85
    'IIS-ODBCLogging'                                             = 86
    'IIS-Performance'                                             = 87
    'IIS-RequestFiltering'                                        = 88
    'IIS-RequestMonitor'                                          = 89
    'IIS-Security'                                                = 90
    'IIS-ServerSideIncludes'                                      = 91
    'IIS-StaticContent'                                           = 92
    'IIS-URLAuthorization'                                        = 93
    'IIS-WebDAV'                                                  = 94
    'IIS-WebServer'                                               = 95
    'IIS-WebServerManagementTools'                                = 96
    'IIS-WebServerRole'                                           = 97
    'IIS-WebSockets'                                              = 98
    'IIS-WindowsAuthentication'                                   = 99
    'IIS-WMICompatibility'                                        = 100
    'IPAMClientFeature'                                           = 101
    'IPAMServerFeature'                                           = 102
    'iSCSITargetServer'                                           = 103
    'iSCSITargetServer-PowerShell'                                = 104
    'iSCSITargetStorageProviders'                                 = 105
    'iSNS_Service'                                                = 106
    'KeyDistributionService-PSH-Cmdlets'                          = 107
    'Licensing'                                                   = 108
    'LightweightServer'                                           = 109
    'ManagementOdata'                                             = 110
    'Microsoft-Hyper-V'                                           = 111
    'Microsoft-Hyper-V-Management-Clients'                        = 112
    'Microsoft-Hyper-V-Management-PowerShell'                     = 113
    'Microsoft-Hyper-V-Offline'                                   = 114
    'Microsoft-Hyper-V-Online'                                    = 115
    'Microsoft-Windows-FCI-Client-Package'                        = 116
    'Microsoft-Windows-GroupPolicy-ServerAdminTools-Update'       = 117
    'MicrosoftWindowsPowerShell'                                  = 118
    'MicrosoftWindowsPowerShellRoot'                              = 119
    'MicrosoftWindowsPowerShellV2'                                = 120
    'Microsoft-Windows-Web-Services-for-Management-IIS-Extension' = 121
    'MSMQ'                                                        = 122
    'MSMQ-ADIntegration'                                          = 123
    'MSMQ-DCOMProxy'                                              = 124
    'MSMQ-HTTP'                                                   = 125
    'MSMQ-Multicast'                                              = 126
    'MSMQ-RoutingServer'                                          = 127
    'MSMQ-Server'                                                 = 128
    'MSMQ-Services'                                               = 129
    'MSMQ-Triggers'                                               = 130
    'MSRDC-Infrastructure'                                        = 131
    'MultipathIo'                                                 = 132
    'MultiPoint-Connector'                                        = 133
    'MultiPoint-Connector-Services'                               = 134
    'MultiPoint-Role'                                             = 135
    'MultiPoint-Tools'                                            = 136
    'NetFx3'                                                      = 137
    'NetFx3ServerFeatures'                                        = 138
    'NetFx4'                                                      = 139
    'NetFx4Extended-ASPNET45'                                     = 140
    'NetFx4ServerFeatures'                                        = 141
    'NetworkDeviceEnrollmentServices'                             = 142
    'NetworkLoadBalancingFullServer'                              = 143
    'OnlineRevocationServices'                                    = 144
    'P2P-PnrpOnly'                                                = 145
    'PeerDist'                                                    = 146
    'PKIClient-PSH-Cmdlets'                                       = 147
    'Printing-Client'                                             = 148
    'Printing-Client-Gui'                                         = 149
    'Printing-LPDPrintService'                                    = 150
    'Printing-PrintToPDFServices-Features'                        = 151
    'Printing-Server-Foundation-Features'                         = 152
    'Printing-Server-Role'                                        = 153
    'Printing-XPSServices-Features'                               = 154
    'QWAVE'                                                       = 155
    'RasRoutingProtocols'                                         = 156
    'RemoteAccess'                                                = 157
    'RemoteAccessMgmtTools'                                       = 158
    'RemoteAccessPowerShell'                                      = 159
    'RemoteAccessServer'                                          = 160
    'Remote-Desktop-Services'                                     = 161
    'ResumeKeyFilter'                                             = 162
    'RightsManagementServices'                                    = 163
    'RightsManagementServices-AdminTools'                         = 164
    'RightsManagementServices-Role'                               = 165
    'RMS-Federation'                                              = 166
    'RPC-HTTP_Proxy'                                              = 167
    'RSAT-ADDS-Tools-Feature'                                     = 168
    'RSAT-AD-Tools-Feature'                                       = 169
    'RSAT-Hyper-V-Tools-Feature'                                  = 170
    'SBMgr-UI'                                                    = 171
    'ServerCore-Drivers-General'                                  = 172
    'ServerCore-Drivers-General-WOW64'                            = 173
    'ServerCore-EA-IME'                                           = 174
    'ServerCore-EA-IME-WOW64'                                     = 175
    'ServerCore-WOW64'                                            = 176
    'ServerForNFS-Infrastructure'                                 = 177
    'ServerManager-Core-RSAT'                                     = 178
    'ServerManager-Core-RSAT-Feature-Tools'                       = 179
    'ServerManager-Core-RSAT-Role-Tools'                          = 180
    'ServerMediaFoundation'                                       = 181
    'ServerMigration'                                             = 182
    'Server-Psh-Cmdlets'                                          = 183
    'ServicesForNFS-ServerAndClient'                              = 184
    'SessionDirectory'                                            = 185
    'SetupAndBootEventCollection'                                 = 186
    'ShieldedVMToolsAdminPack'                                    = 187
    'SimpleTCP'                                                   = 188
    'SMB1Protocol'                                                = 189
    'SMBBW'                                                       = 190
    'SmbDirect'                                                   = 191
    'SMBHashGeneration'                                           = 192
    'SmbWitness'                                                  = 193
    'Smtpsvc-Admin-Update-Name'                                   = 194
    'Smtpsvc-Service-Update-Name'                                 = 195
    'SNMP'                                                        = 196
    'Storage-Replica-AdminPack'                                   = 197
    'Storage-Services'                                            = 198
    'TelnetClient'                                                = 199
    'TlsSessionTicketKey-PSH-Cmdlets'                             = 200
    'Tpm-PSH-Cmdlets'                                             = 201
    'UpdateServices'                                              = 202
    'UpdateServices-API'                                          = 203
    'UpdateServices-Database'                                     = 204
    'UpdateServices-RSAT'                                         = 205
    'UpdateServices-Services'                                     = 206
    'UpdateServices-WidDatabase'                                  = 207
    'VmHostAgent'                                                 = 208
    'VolumeActivation-Full-Role'                                  = 209
    'WAS-ConfigurationAPI'                                        = 210
    'WAS-NetFxEnvironment'                                        = 211
    'WAS-ProcessModel'                                            = 212
    'WAS-WindowsActivationService'                                = 213
    'WCF-HTTP-Activation'                                         = 214
    'WCF-HTTP-Activation45'                                       = 215
    'WCF-MSMQ-Activation45'                                       = 216
    'WCF-NonHTTP-Activation'                                      = 217
    'WCF-Pipe-Activation45'                                       = 218
    'WCF-Services45'                                              = 219
    'WCF-TCP-Activation45'                                        = 220
    'WCF-TCP-PortSharing45'                                       = 221
    'WebAccess'                                                   = 222
    'Web-Application-Proxy'                                       = 223
    'WebEnrollmentServices'                                       = 224
    'Windows-Defender'                                            = 225
    'Windows-Defender-Features'                                   = 226
    'Windows-Internal-Database'                                   = 227
    'WindowsPowerShellWebAccess'                                  = 228
    'WindowsServerBackup'                                         = 229
    'WindowsStorageManagementService'                             = 230
    'WINSRuntime'                                                 = 231
    'WINS-Server-Tools'                                           = 232
    'WMISnmpProvider'                                             = 233
    'WorkFolders-Server'                                          = 234
    'WSS-Product-Package'                                         = 235
}
$osRegistryPath = 'REGISTRY::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osRegistryProperties = @(
    'CurrentBuild'
    'CurrentType'
    'CurrentVersion'
    'DisplayVersion'
    'EditionID'
    'InstallationType'
    'InstallDate'
    'ProductName'
    'ProductId'
    'RegisteredOrganization'
    'RegisteredOwner'
)
$excludeTaskAuthors = @(
    'Adobe Systems Incorporated'
    'Dell, Inc.'
    'Lenovo'
    'Microsoft'
    'Microsoft Corporation'
    'Mozilla'
    'NVIDIA Corporation'
    'Realtek'
)
$excludeTaskAuthorRegex = '^(Citrix).*$'
$excludeTaskNameRegex = '^((BITS)|(Git)|(Google)|(Intel)|(IUM)|(MicrosoftEdge)|(Optimize Start Menu)|(User_Feed_Sync)).*$'
$excludeTaskPathRegex = '^\\((Lenovo)|(Microsoft)).*$'

[void]$logData.Append("$env:COMPUTERNAME || $($date.ToString('yyyy-MM-ddTHH:mm:ssL')) || $InfoType || ")
if ($Win32Class) { [void]$logData.Append("$Win32Class || ") }
[void]$logData.AppendLine("Start")

$obj = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Details      = $null
}

Switch ($InfoType) {
    'Cluster' {
        try {
            $details = [PSCustomObject]@{
                Cluster       = $null
                ClusterNodes  = $null
                ClusterGroups = $null
            }
            $details.Cluster = (Get-Cluster -ErrorAction Stop).Name
            $details.ClusterNodes = Get-ClusterNode | Select-Object -Property Id, Name, State | Sort-Object -Property Id
            $details.ClusterGroups = Get-ClusterGroup | Select-Object -Property Name, State, @{Label = 'OwnerNode'; Expression = { (Get-ClusterNode -Name $($_.OwnerNode).ToString()).Id } } | Sort-Object -Property Name
            [void]$logData.AppendLine("InfoStart::")
            [void]$logData.AppendLine("Cluster: $($details.Cluster)")
            ForEach ($node in $details.ClusterNodes) {
                [void]$logData.AppendLine("Id: $($node.Id) || Name: $($node.Name) || State: $($node.State)")
            }
            ForEach ($group in $details.ClusterGroups) {
                [void]$logData.AppendLine("Name: $($group.Name) || State: $($group.State) || OwnerNode: $($group.OwnerNode)")
            }
            [void]$logData.AppendLine("::InfoEnd")
            $obj.Details = $details
        }
        catch {
            $details = [PSCustomObject]@{
                Cluster       = 'None'
                ClusterNodes  = @($([PSCustomObject]@{ Id = 'None'; Name = 'None'; State = 'None' }))
                ClusterGroups = @($([PSCustomObject]@{ Name = 'None'; State = 'None'; OwnerNode = 'None' }))
            }
            [void]$logData.AppendLine("InfoStart::")
            [void]$logData.AppendLine("NoCluster")
            [void]$logData.AppendLine("::InfoEnd")
            $obj.Details = $details
        }
        finally {
            $logData.ToString() | Out-File -FilePath $LogPath -Append
            if ($OutputType -eq 'String') {
                $output = New-Object -TypeName System.Text.StringBuilder
                [void]$output.Append("$env:COMPUTERNAME || Cluster: $($details.Cluster) - Nodes: $($details.ClusterNodes.Count) - Groups: $($details.ClusterGroups.Count)")
                $output = $output.ToString()
            }
            else {
                if (!($Name)) {
                    if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                        $output = [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Details      = [PSCustomObject]@{
                                C  = $obj.Details.Cluster
                                CN = [System.Collections.Generic.List[System.Object]]::New()
                                CG = [System.Collections.Generic.List[System.Object]]::New()
                            }
                        }
                        ForEach ($d in $obj.Details.ClusterNodes) {
                            $output.Details.CN.Add($([PSCustomObject]@{ I = $d.Id; N = $d.Name; S = $d.State }))
                        }
                        ForEach ($d in $obj.Details.ClusterGroups) {
                            $output.Details.CG.Add($([PSCustomObject]@{ N = $d.Name; S = $d.State; O = $d.OwnerNode }))
                        }
                        if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                            $output.Details = 'EXCEEDS'
                        }
                    }
                    else {
                        $output = $obj
                    }
                }
                else {
                    if ($Name -in $_.ClusterGroups.Name) {
                        $obj.Details = $obj.Details | Where-Object { $_.ClusterGroups.Name -eq $Name }
                        $output = $obj
                    }
                    else {
                        $output = $obj
                    }
                }
            }
        }
    }
    'DefaultService' {
        if (!($Name)) {
            $details = Get-Service | Where-Object { $_.Name -in $defaultServiceList.Keys } | Select-Object -Property Name, Status | Sort-Object -Property Name
        }
        else {
            if ($null -eq $(Get-Service -DisplayName $Name -ErrorAction SilentlyContinue)) {
                if ($null -eq $(Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
                    $details = @($([PSCustomObject]@{ Name = 'None'; Status = 0 }))
                }
                else {
                    $details = Get-Service -Name $Name | Select-Object -Property Name, Status
                }
            }
            else {
                $details = Get-Service -DisplayName $Name | Select-Object -Property Name, Status
            }
        }
        [void]$logData.AppendLine("InfoStart::")
        $returnDetails = [System.Collections.Generic.List[System.Object]]::New()
        ForEach ($dServ in $details) {
            [void]$logData.AppendLine("Name: $($dServ.Name) || Status: $($dServ.Status)")
            $returnDetails.Add(
                $([PSCustomObject]@{
                        Name   = $defaultServiceList.$($dServ.Name)
                        Status = $serviceStatusHash.$($dServ.Status.ToString())
                    })
            )
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $returnDetails
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || ")
            ForEach ($status in $($details.Status | Sort-Object -Unique)) {
                [void]$output.Append("${status}: $(($details | Where-Object { $_.Status -eq $status }).Count) - ")
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
                    $output.Details.Add($([PSCustomObject]@{ N = $d.Name; S = $d.Status }))
                }
                if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                    $output.Details = 'EXCEEDS'
                }
            }
            else {
                $output = $obj
            }
        }
    }
    'DesktopExperience' {
        $details = Get-ItemProperty -Path $osRegistryPath | Select-Object -Property $osRegistryProperties
        [void]$logData.AppendLine("InfoStart::")
        ForEach ($member in $((Get-Member -InputObject $details -MemberType -NoteProperty).Name | Sort-Object)) {
            [void]$logData.AppendLine("${member}: $($details.$member)")
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $details
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || Type: $($details.InstallationType)")
            $output = $output.ToString()
        }
        else {
            if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                $obj.Details = 'EXCEEDS'
            }
            $output = $obj
        }
    }
    'DriveSpace' {
        [void]$logData.AppendLine("InfoStart::")
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $null -eq $_.DisplayRoot } `
        | Select-Object -Property Name, @{Name = 'Used'; Expression = { $([math]::Round($_.Used / 1GB, 2)) } }, @{Name = 'Free'; Expression = { $([math]::Round($_.Free / 1GB, 2)) } }, @{Name = 'Total'; Expression = { $([math]::Round($($_.Used + $_.Free) / 1GB, 2)) } } `
        | Sort-Object -Property Name
        if ($Name) { $drives = $drives | Where-Object { $_.Name -eq $Name } }
        if ($drives.Count -eq 0) { $drives = @($([PSCustomObject]@{ Name = 'None'; Used = 0; Free = 0; Total = 0 })) }
        ForEach ($d in $drives) {
            [void]$logData.AppendLine("DriveName: $($d.Name) || Used: $($d.Used.ToString('#.00')) GB || Free: $($d.Free.ToString('#.00')) GB || Total: $($d.Total.ToString('#.00')) GB")
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $drives
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || ")
            $drives | ForEach-Object {
                [void]$output.Append("$($_.Name): $($_.Free.ToString('#.00')) || ")
            }
            $output = $output.ToString().TrimEnd(' || ')
        }
        else {
            $output = $obj
        }
    }
    'IIS' {
        try {
            $details = Get-IISSite -ErrorAction Stop | Select-Object -Property Name, State, @{Label = 'Bindings'; Expression = { "$($_.Bindings.protocol):$($_.Bindings.bindingInformation)" } }, @{Label = 'SSL'; Expression = { $_.Bindings.sslFlags } }
        }
        catch {
            $details = @($([PSCustomObject]@{ Name = 'None'; State = 'None'; Bindings = 'None'; SSL = 'None' }))
        }
        [void]$logData.AppendLine("InfoStart::")
        ForEach ($d in $details) {
            [void]$logData.AppendLine("Name: $($d.Name) || State: $($d.State) || Bindings: $($d.Bindings) || SSL: $($d.SSL)")
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $details
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME")
            $details | ForEach-Object {
                [void]$output.Append(" || $($_.Name): $($_.State)")
            }
            $output = $output.ToString()
        }
        else {
            $output = $obj
        }
    }
    'InstalledPatches' {
        try {
            if (!($Name)) {
                $details = Get-Hotfix -ErrorAction Stop | Select-Object -Property @{Label = 'HotFixID'; Expression = { $_.HotFixID.TrimStart('KB').ToString() } }, @{Label = 'Type'; Expression = { $_.Description } } | Sort-Object -Property HotFixID
            }
            else {
                try {
                    $details = Get-Hotfix -Id $Name -ErrorAction Stop | Select-Object -Property @{Label = 'HotFixID'; Expression = { $_.HotFixID.TrimStart('KB').ToString() } }, @{Label = 'Type'; Expression = { $_.Description } }
                }
                catch {
                    $details = @($([PSCustomObject]@{ HotFixID = 'None'; Type = 'None' }))
                }
            }
        }
        catch {
            $details = @($([PSCustomObject]@{ HotFixID = 'None'; Type = 'None' }))
        }
        [void]$logData.AppendLine("InfoStart::")
        ForEach ($patch in $details) {
            [void]$logData.AppendLine("HotFixID: $($patch.HotFixID) || Type: $($patch.Type)")
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $details
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || Patches: $($details.Count)")
            $output = $output.ToString()
        }
        else {
            $obj.Details | ForEach-Object {
                $_.Type = $patchDescriptionHash[$($_.Type)]
            }
            if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                $output = [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Details      = [System.Collections.Generic.List[System.Object]]::New()
                }
                ForEach ($d in $obj.Details) {
                    $output.Details.Add($([PSCustomObject]@{ HF = $d.HotFixID; T = $d.Type }))
                }
                if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                    $output = [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        Details      = $output.Details.HF
                    }
                    if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                        $output.Details = 'EXCEEDS'
                    }
                }
            }
            else {
                $output = $obj
            }
        }
    }
    'PatchingStatus' {
        $details = Get-WmiObject -Namespace root\ccm\clientSDK -Class CCM_SoftwareUpdate | Select-Object -Property ArticleID, EvaluationState, @{Label = 'ErrorCode'; Expression = { $_.ErrorCode.ToString('x').ToUpper() } }, PercentComplete
        [void]$logData.AppendLine("InfoStart::")
        if (@($details).Count -eq 0) {
            $details = @([PSCustomObject]@{ ArticleID = 'None'; EvaluationState = 'None'; ErrorCode = 'None'; PercentComplete = 'None' })
            [void]$logData.AppendLine("ArticleID: None || EvaluationState: None || ErrorCode: None || PercentComplete: None")
        }
        else {
            ForEach ($update in $details) {
                [void]$logData.AppendLine("ArticleID: $($update.ArticleID) || EvaluationState: $($evalHash.Values.$($update.EvaluationState)) || ErrorCode: $($update.ErrorCode) || PercentComplete: $($update.PercentComplete.ToString())")
            }
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $details
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || ")
            ForEach ($evalState in $($details.EvaluationState | Sort-Object -Unique)) {
                [void]$output.Append("$($evalHash.$($evalState)): $(($details | Where-Object { $_.EvaluationState -eq $evalState }).Count) - ")
            }
            $output = $output.ToString.TrimEnd(' - ')
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
    }
    'PatchWindow' {
        [void]$logData.AppendLine("InfoStart::")
        if (Test-Path -Path $RegistryPath) {
            $reg = Get-Item -Path $RegistryPath
            if ($RegistryName -in $reg.Property) {
                [void]$logData.AppendLine("${PatchWindowRegistryName}: $($reg.GetValue($RegistryName))")
                $details = $reg.GetValue($RegistryName)
            }
            else {
                [void]$logData.AppendLine("${PatchWindowRegistryName}: NoValue")
                $details = 'NO_VALUE_EXISTS'
            }
        }
        else {
            [void]$logData.AppendLine("${PatchWindowRegistryPath}: NoKey")
            $details = 'NO_KEY_EXISTS'
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $details
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || Path: $($RegistryPath) - Name: $($RegistryName) - Result: $($details)")
            $output = $output.ToString()
        }
        else {
            if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                $obj.Details = 'EXCEEDS'
            }
            $output = $obj
        }
    }
    'Service' {
        if (!($Name)) {
            $details = Get-Service -Exclude $([System.String[]]$defaultServiceList.Keys) | Select-Object -Property Name, Status
        }
        else {
            if ($null -eq $(Get-Service -DisplayName $Name -ErrorAction SilentlyContinue)) {
                if ($null -eq $(Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
                    $details = @($([PSCustomObject]@{ Name = 'None'; Status = 0 }))
                }
                else {
                    $details = Get-Service -Name $Name | Select-Object -Property Name, Status
                }
            }
            else {
                $details = Get-Service -DisplayName $Name | Select-Object -Property Name, Status
            }
        }
        [void]$logData.AppendLine("InfoStart::")
        ForEach ($service in $details) {
            [void]$logData.AppendLine("Name: $($service.Name) || Status: $($service.Status)")
            $service.Status = $serviceStatusHash.$($service.Status.ToString())
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $details
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || ")
            ForEach ($status in $($details.Status | Sort-Object -Unique)) {
                [void]$output.Append("${status}: $(($details | Where-Object { $_.Status -eq $status }).Count) - ")
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
                    $output.Details.Add($([PSCustomObject]@{ N = $d.Name; S = $d.Status }))
                }
                if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                    $output.Details = 'EXCEEDS'
                }
            }
            else {
                $output = $obj
            }
        }
    }
    'Task' {
        if (!($Name)) {
            $details = Get-ScheduledTask `
            | Where-Object { ($_.Author -notin $excludeTaskAuthors -and $_.Author -notmatch $excludeTaskAuthorRegex) -and $_.TaskName -notmatch $excludeTaskNameRegex -and $_.TaskPath -notmatch $excludeTaskPathRegex } `
            | Select-Object -Property TaskName, @{Label = 'State'; Expression = { $_.State.ToString() } } | Sort-Object -Property TaskName
        }
        else {
            try {
                $details = Get-ScheduledTask -TaskName $Name -ErrorAction Stop | Select-Object -Property TaskName, @{Label = 'State'; Expression = { $_.State.ToString() } }
            }
            catch {
                $details = @($([PSCustomObject]@{ TaskName = 'None'; State = 0 }))
            }
        }
        [void]$logData.AppendLine("InfoStart::")
        ForEach ($task in $details) {
            [void]$logData.AppendLine("TaskName: $($task.TaskName) || State: $($task.State)")
            $task.State = $taskStateHash.$($task.State)
        }
        [void]$logData.AppendLine("::InfoEnd")
        $obj.Details = $details
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || ")
            ForEach ($state in $($details.State | Sort-Object -Unique)) {
                [void]$output.Append("${state}: $(($details | Where-Object { $_.State -eq $state }).Count) - ")
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
                    $output.Details.Add($([PSCustomObject]@{ TN = $d.TaskName; S = $d.State }))
                }
                if ($($output | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                    $output.Details = 'EXCEEDS'
                }
            }
            else {
                $output = $obj
            }
        }
    }
    'Win32Class' {
        [void]$logData.AppendLine("InfoStart::")
        Switch ($Win32Class) {
            'BaseBoard' { $properties = 'Product', 'Manufacturer', 'SerialNumber', 'Version' }
            'BIOS' { $properties = 'Manufacturer', 'SerialNumber', 'SMBIOSBIOSVersion', 'Version' }
            'ComputerSystem' { $properties = 'Domain', 'Model', 'Manufacturer', 'SystemType' }
            'ComputerSystemProduct' { $properties = 'IdentifyingNumber', 'UUID', 'Vendor' }
            'DiskDrive' { $properties = 'Index', 'Caption', 'Model', 'SerialNumber', 'FirmwareRevision', 'Status' }
            'DiskPartition' { $properties = 'DiskIndex', 'Index', 'Description' }
            'LogicalDisk' { $properties = 'Name', 'Size', 'FreeSpace', 'DriveType', 'FileSystem', 'Description', 'VolumeSerialNumber', 'Compressed', 'VolumeDirty' }
            'NetworkAdapter' { $properties = 'Name', 'MACAddress', 'Manufacturer', 'Speed', 'NetConnectionID', 'NetEnabled', 'PhysicalAdapter' }
            'OperatingSystem' { $properties = 'Caption', 'Version', 'OSArchitecture', 'SerialNumber', 'FreePhysicalMemory', 'FreeVirtualMemory', 'TotalVirtualMemorySize', 'TotalVisibleMemorySize' }
            'OptionalFeature' { $properties = 'Name', 'InstallState' }
            'PhysicalMemory' { $properties = 'Name', 'DeviceLocator', 'FormFactor', 'MemoryType', 'Speed', 'Capacity', 'DataWidth', 'TotalWidth', 'TypeDetail', 'SerialNumber', 'Manufacturer', 'PartNumber' }
            'Process' { $properties = 'ProcessName', 'Handles', 'VM', 'WS' }
            'Processor' { $properties = 'Name', 'Description', 'NumberOfCores', 'CurrentClockSpeed', 'L3CacheSize', 'Status', 'Manufacturer', 'ProcessorId' }
        }
        $className = "Win32_$($Win32Class)"
        $details = Get-WmiObject -ClassName $className | Select-Object -Property $properties | Sort-Object -Property $properties[0]
        if (@($details).Count -ne 0) {
            $obj.Details = $details | ForEach-Object {
                Switch ($Win32Class) {
                    'BaseBoard' {
                        [void]$logData.AppendLine("Product: $($_.Product) || Manufacturer: $($_.Manufacturer) || SerialNumber: $($_.SerialNumber) || Version: $($_.Version)")
                    }
                    'BIOS' {
                        [void]$logData.AppendLine("Manufacturer: $($_.Manufacturer) || SerialNumber: $($_.SerialNumber) || SMBIOSBIOSVersion: $($_.SMBIOSBIOSVersion) || Version: $($_.Version)")
                    }
                    'ComputerSystem' {
                        [void]$logData.AppendLine("Domain: $($_.Domain) || Model: $($_.Model) || Manufacturer: $($_.Manufacturer) || SystemType: $($_.SystemType)")
                    }
                    'ComputerSystemProduct' {
                        [void]$logData.AppendLine("IdentifyingNumber: $($_.IdentifyingNumber) || UUID: $($_.UUID) || Vendor: $($_.Vendor)")
                    }
                    'DiskDrive' {
                        [void]$logData.AppendLine("Index: $($_.Index) || Caption: $($_.Caption) || Model: $($_.Model) || SerialNumber: $($_.SerialNumber) || FirmwareRevision: $($_.FirmwareRevision) || Status: $($_.Status)")
                        [PSCustomObject]@{ I = $_.Index; C = $_.Caption; M = $_.Model; SN = $_.SerialNumber; FWR = $_.FirmwareRevision; S = $_.Status }
                    }
                    'DiskPartition' {
                        [void]$logData.AppendLine("DiskIndex: $($_.DiskIndex) || Index: $($_.Index) || Description: $($_.Description)")
                        [PSCustomObject]@{ DI = $_.DiskIndex; I = $_.Index; D = $_.Description }
                    }
                    'LogicalDisk' {
                        [void]$logData.AppendLine("Name: $($_.Name) || Size: $($_.Size) || FreeSpace: $($_.FreeSpace) || DriveType: $($_.DriveType) || FileSystem: $($_.FileSystem) || Description: $($_.Description) || VolumeSerialNumber: $($_.VolumeSerialNumber) || Compressed: $($_.Compressed) || VolumeDirty: $($_.VolumeDirty)")
                        [PSCustomObject]@{ N = $_.Name; S = $_.Size; F = $_.FreeSpace; DT = $_.DriveType; FS = $_.FileSystem; D = $_.Description; VSN = $_.VolumeSerialNumber; C = $_.Compressed; VD = $_.VolumeDirty }
                    }
                    'NetworkAdapter' {
                        [void]$logData.AppendLine("Name: $($_.Name) || MACAddress: $($_.MACAddress) || Manufacturer: $($_.Manufacturer) || Speed: $($_.Speed) || NetConnectionID: $($_.NetConnectionID) || NetEnabled: $($_.NetEnabled) || PhysicalAdapter: $($_.PhysicalAdapter)")
                        [PSCustomObject]@{ N = $_.Name; MAC = $_.MACAddress; M = $_.Manufacturer; SPD = $_.Speed; NCID = $_.NetConnectionID; NE = $_.NetEnabled; PA = $_.PhysicalAdapter }
                    }
                    'OperatingSystem' {
                        [void]$logData.AppendLine("Caption: $($_.Caption) || Version: $($_.Version) || OSArchitecture: $($_.OSArchitecture) || SerialNumber: $($_.SerialNumber) || FreePhysicalMemory: $($_.FreePhysicalMemory) || FreeVirtualMemory: $($_.FreeVirtualMemory) || TotalVirtualMemorySize: $($_.TotalVirtualMemorySize) || TotalVisibleMemorySize: $($_.TotalVisibleMemorySize)")
                    }
                    'OptionalFeature' {
                        [void]$logData.AppendLine("Name: $($_.Name) || InstallState: $($_.InstallState)")
                        [PSCustomObject]@{ N = $optionalFeatureHash.$($_.Name); IS = $_.InstallState }
                    }
                    'PhysicalMemory' {
                        [void]$logData.AppendLine("Name: $($_.Name) || DeviceLocator: $($_.DeviceLocator) || FormFactor: $($_.FormFactor) || MemoryType: $($_.MemoryType) || Speed: $($_.Speed) || Capacity: $($_.Capacity) || DataWidth: $($_.DataWidth) || TotalWidth: $($_.TotalWidth) || TypeDetail: $($_.TypeDetail) || SerialNumber: $($_.SerialNumber) || Manufacturer: $($_.Manufacturer) || PartNumber: $($_.PartNumber)")
                        [PSCustomObject]@{ N = $_.Name; DL = $_.DeviceLocator; FF = $_.FormFactor; MT = $_.MemoryType; SPD = $_.Speed; C = $_.Capacity; DW = $_.DataWidth; TW = $_.TotalWidth; TD = $_.TypeDetail; SN = $_.SerialNumber; MF = $_.Manufacturer; PN = $_.PartNumber }
                    }
                    'Process' {
                       [void]$logData.AppendLine("ProcessName: $($_.ProcessName) || Handles: $($_.Handles) || VM: $($_.VM) || WS: $($_.WS)")
                       [PSCustomObject]@{ PN = $_.ProcessName; H = $_.Handles; VM = $_.VM; WS = $_.WS }
                    }
                    'Processor' {
                        [void]$logData.AppendLine("Name: $($_.Name) || Description: $($_.Description) || NumberOfCores: $($_.NumberOfCores) || CurrentClockSpeed: $($_.CurrentClockSpeed) || L3CacheSize: $($_.L3CacheSize) || Status: $($_.Status) || Manufacturer: $($_.Manufacturer) || ProcessorId: $($_.ProcessorId)")
                    }
                }
            }
        }
        else {
            [void]$logData.AppendLine("Class: $($Win32Class) || Found: None")
            $obj.Details = @($([PSCustomObject]@{ Class = $Win32Class; Found = 'None' }))
        }
        [void]$logData.AppendLine("::InfoEnd")
        $logData.ToString() | Out-File -FilePath $LogPath -Append
        if ($OutputType -eq 'String') {
            $output = New-Object -TypeName System.Text.StringBuilder
            [void]$output.Append("$env:COMPUTERNAME || ${InfoType} || ${Win32Class} || Complete")
            $output = $output.ToString()
        }
        else {
            if ($($obj | ConvertTo-Json -Depth 100 -Compress).Length -gt 4000) {
                $obj.Details = 'EXCEEDS'
            }
            $output = $obj
        }
    }
}
$output
