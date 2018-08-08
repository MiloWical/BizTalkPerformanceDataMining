<#
.SYNOPSIS
PowerShell script to perform a quick BizTalk Health Check
.DESCRIPTION
This script gathers and displays a lot of information about a BizTalk server. Sections include Windows, Computer, BizTalk artifacts, Event Logs and more.
IMPORTANT! The script will check the environment it's run from. This means if you run the script from a PROD server, it will connect to the PROD BizTalk database.
.EXAMPLE
./BizTalkHealthCheck.ps1
.NOTES
You need to be member of BizTalk Server Administrators group to run this script. No parameters.
#>
Clear-Host
$startTime = Get-Date
Write-Host "Collect Date/Time:" $startTime
Write-Host "Current User:" ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

try { # Get BizTalk Information
    $BizTalkGroup = Get-WmiObject MSBTS_GroupSetting -namespace root\MicrosoftBizTalkServer -ErrorAction Stop
    $BizTalkMsgBoxDb = Get-WmiObject MSBTS_MsgBoxSetting -namespace root\MicrosoftBizTalkServer -ErrorAction Stop
    $BizTalkServer = Get-WmiObject MSBTS_Server -namespace root\MicrosoftBizTalkServer -ErrorAction Stop
    $BizTalkREG = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\BizTalk Server\3.0" -ErrorAction Stop
    $hostInstances = Get-WmiObject MSBTS_HostInstance -namespace root\MicrosoftBizTalkServer -ErrorAction Stop
    $trackingHost = Get-WmiObject MSBTS_Host -Namespace root\MicrosoftBizTalkServer -ErrorAction Stop | Where-Object {$_.HostTracking -eq "true" }
    [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.BizTalk.ExplorerOM")
    $BizTalkDBInstance = $BizTalkGroup.MgmtDbServerName
    $BizTalkDB = $BizTalkGroup.MgmtDbName
    $BizTalkOM = New-Object Microsoft.BizTalk.ExplorerOM.BtsCatalogExplorer
    $BizTalkOM.ConnectionString = "SERVER=$BizTalkDBInstance;DATABASE=$BizTalkDB;Integrated Security=SSPI"
}
catch {
    Write-Host "BizTalk not detected on this machine, or user not member of BizTalk Administrators group" -fore Red
    exit
}

# Display BizTalk Information
Write-Host "`nBizTalk Information" -fore Green
Write-Host $BiztalkREG.ProductName "("$BiztalkREG.ProductEdition"Edition )"
Write-Host "Product Version:" $BiztalkREG.ProductVersion
Write-Host "Installation Path:" $BiztalkREG.InstallPath
Write-Host "Installation Date:" $BiztalkREG.InstallDate
Write-Host "Server name:" $BiztalkServer.Name
Write-Host "SSO Server:" $BizTalkGroup.SSOServerName
Write-Host "BizTalk Admin group:" $BizTalkGroup.BizTalkAdministratorGroup
Write-Host "BizTalk Operators group:" $BizTalkGroup.BizTalkOperatorGroup
Write-Host "BizTalk Group Name:" $BizTalkGroup.Name
Write-Host "Cache Refresh Interval:" $BizTalkGroup.ConfigurationCacheRefreshInterval

switch ($BizTalkGroup.GlobalTrackingOption) {
    0 { Write-Host "Global Tracking: Off" }
    1 { Write-Host "Global Tracking: On" }
}
Write-Host "`nInstalled BizTalk Software" -Fore DarkGray
Get-WmiObject win32_product | where-object { $_.Name -like "*BizTalk*" } | select-object Name -Unique | Sort-Object Name | Select-Object -expand Name

# Display BizTalk Host Instance Information
Write-Host "`nHost Instance Information ("$hostInstances.Count")" -fore DarkGray

foreach ($hostInstance in $hostInstances) {
    switch ($hostInstance.servicestate) {
        1 { $hostInstanceState = "Stopped" }
        2 { $hostInstanceState = "Start pending" }
        3 { $hostInstanceState = "Stop pending" }
        4 { $hostInstanceState = "Running" }
        5 { $hostInstanceState = "Continue pending" }
        6 { $hostInstanceState = "Pause pending" }
        7 { $hostInstanceState = "Paused" }
        8 { $hostInstanceState = "Unknown" }
    }
    switch ($hostInstance.HostType) {
        1 { $hostInstanceType = "In-process" }
        2 { $hostInstanceType = "Isolated" }
    }
    if ($hostInstanceState -eq "Running") {
        Write-Host $hostInstance.hostname "($hostInstanceType)" "- "  -NoNewline
        Write-Host $hostInstanceState -fore green
    }
    elseif ($hostInstanceState -eq "Stopped") {
            if ($hostInstance.IsDisabled -eq $true ) {
                Write-Host $hostInstance.hostname "($hostInstanceType)" "- " -NoNewline
                Write-Host $hostInstanceState "(Disabled)" -fore red
            }
            else {
                Write-Host $hostInstance.hostname "($hostInstanceType)" "- " -NoNewline
                Write-Host $hostInstanceState -fore Red
            }
    }
    else {
        if ($hostInstanceType -eq "In-process") {
            Write-Host $hostInstance.hostname "($hostInstanceType)" "- " -NoNewline
            Write-Host $hostInstanceState "(Disabled:$($hostInstance.IsDisabled))" -fore DarkYellow
        }
        else {
            Write-Host $hostInstance.hostname "($hostInstanceType)"
        }
    }
}
Write-Host "`nTracking Host(s)" -Fore DarkGray
$trackingHost.Name

# Get BizTalk Application Information
$applications = $BizTalkOM.Applications

# Display BizTalk Application Information
Write-Host "`nBizTalk Applications ("$applications.Count")" -fore DarkGray

Foreach ($application in $applications) {
    if ($application.Status -eq "Started") {
        Write-Host $application.Name "- " -NoNewline
        Write-Host $application.Status -fore Green
    }
    elseif ($application.Status -eq "Stopped") {
        Write-Host $application.Name "- " -NoNewline
        Write-Host $application.Status -fore Red
    }
    else {
        Write-Host $application.Name "- " -NoNewline
        Write-Host $application.Status -fore DarkYellow
    }
}

# Get BizTalk Service Instance Information
[ARRAY]$readyToRun = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 1)' -ErrorAction SilentlyContinue
[ARRAY]$active = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 2) and not(ServiceClass = 16)' -ErrorAction SilentlyContinue
[ARRAY]$dehydrated = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 8)' -ErrorAction SilentlyContinue
[ARRAY]$breakpoint = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 64)' -ErrorAction SilentlyContinue
[ARRAY]$suspendedOrchs = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 1) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue
[ARRAY]$suspendedMessages = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 4) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue
[ARRAY]$suspendedRouting = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 64)' -ErrorAction SilentlyContinue
[ARRAY]$suspendedIsolated = get-wmiobject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 32) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue

# Display BizTalk Service Instance Information
Write-Host "`nService Instance Information" -fore DarkGray
Write-Host "Instances Ready to Run:" $readyToRun.Count
Write-Host "Active Instances:" $active.Count
Write-Host "Dehydrated Instances:" $dehydrated.Count
Write-Host "Instances in Breakpoint:" $breakpoint.Count
Write-Host "Suspended Orchestrations:" $suspendedOrchs.count
Write-Host "Suspended Messages:" $suspendedMessages.count
Write-Host "Routing Failures:" $suspendedRouting.count
Write-Host "Isolated Adapter Failures:" $suspendedIsolated.count

# Get and Display BizTalk Receive Location Information
[ARRAY]$recLocs = get-wmiobject MSBTS_ReceiveLocation -namespace 'root\MicrosoftBizTalkServer' | Where-Object {$_.IsDisabled -eq "true" }
Write-Host "`nDisabled Receive Locations (" $recLocs.Count ")" -fore DarkGray

if ($recLocs.Count -gt 0) { $recLocs.Name }
else { Write-Host "None" }

# Get and Display BizTalk Send Port Information
[ARRAY]$sendPorts = get-wmiobject MSBTS_SendPort -namespace 'root\MicrosoftBizTalkServer' | Where-Object {$_.Status -eq 2 -or $_.Status -eq 1}
Write-Host "`nStopped and Unenlisted Send Ports (" $sendPorts.Count ")" -fore DarkGray

if ($sendPorts.Count -gt 0) { $sendPorts.Name }
else { Write-Host "None" }

# Get and Display Orchstrations not started
[ARRAY]$orchs = Get-WmiObject MSBTS_Orchestration -namespace 'root\MicrosoftBizTalkServer' | Where-Object {$_.OrchestrationStatus -ne 4 }
Write-Host "`nNot Started Orchestrations (" $orchs.Count ")" -fore DarkGray

if ($orchs.Count -gt 0) { $orchs.Name }
else { Write-Host "None" }

# Tracking
Write-Host "`nTracking" -fore DarkGray
[ARRAY]$trackingSendPorts = get-wmiobject MSBTS_SendPort -namespace 'root\MicrosoftBizTalkServer' | Where-Object {$_.Tracking -gt 0 }
[ARRAY]$trackingRecPorts = get-wmiobject MSBTS_ReceivePort -namespace 'root\MicrosoftBizTalkServer' | Where-Object {$_.Tracking -gt 0 }
Write-Host "Receive Ports with Tracking:" $trackingRecPorts.Count
Write-Host "Send Ports with Tracking:" $trackingSendPorts.Count

# Get and Display Windows Information
Write-Host "`nWindows Information" -fore Green
$windowsDetails = Get-WmiObject -Class Win32_OperatingSystem
Write-Host $windowsDetails.Caption
Write-Host "Product Version:" $windowsDetails.Version
Write-Host "Service Pack Level:" $windowsDetails.CSDVersion
$UpdateSession = New-Object -Com Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
Write-Host "Missing Windows Updates:" $SearchResult.Updates.Count
Write-Host "Architecture:" $windowsDetails.OSArchitecture
Write-Host "Installation Path:" $windowsDetails.WindowsDirectory
Write-Host "Page File:" (Get-WmiObject Win32_PageFileUsage).Name
Write-Host "TEMP Folder:" $env:TEMP "("(Get-ChildItem $env:TEMP -File -Recurse | Measure-Object).count" file(s) )"
Write-Host "TMP Folder:" $env:TMP "("(Get-ChildItem $env:TMP -File -Recurse | Measure-Object).count" file(s) )"
if (Test-Path C:\temp) {
    Write-Host "C:\Temp:" (Get-ChildItem C:\temp -File -Recurse | Measure-Object).Count "file(s)"
}

Import-Module ServerManager
Get-WindowsFeature | Where-Object {$_.Installed -eq $True} | Sort-Object DisplayName | Format-Table @{Expression={$_.DisplayName};Label="Installed Windows Roles and Features"}

# Display IIS information
try {
    Import-Module WebAdministration
    Write-Host "IIS Version:" (get-itemproperty HKLM:\SOFTWARE\Microsoft\InetStp\).setupstring
    Write-Host "`nApplication Pools" -Fore DarkGray -NoNewLine
    Get-ChildItem IIS:\apppools | Format-Table -AutoSize
}
catch {
    Write-Host "Unable to perform IIS checks" -fore Red
}

# Check Windows Service state
function FuncCheckService{
     param($ServiceName)
         $arrService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue 
         if ($arrService.Status -eq "Running"){ 
            Write-Host $ServiceName "is running"
            $script:unnecessaryServices++
         }
}
Write-Host("Unnecessary Windows Services") -Fore DarkGray
[int]$script:unnecessaryServices = 0
FuncCheckService("Print Spooler")
FuncCheckService("Alerter")
FuncCheckService("ClipBook")
FuncCheckService("DHCP Server")
FuncCheckService("Fax Service")
FuncCheckService("File Replication")
FuncCheckService("Infrared Monitor")
FuncCheckService("Internet Connection Sharing")
FuncCheckService("Messenger")
FuncCheckService("NetMeeting Remote Desktop Sharing")
FuncCheckService("Network DDE")
FuncCheckService("Network DDE DSDM")
FuncCheckService("NWLink NetBIOS")
FuncCheckService("NWLink IPX/SP")
FuncCheckService("Telephony")
FuncCheckService("Telnet")
FuncCheckService("Uninterruptible Power Supply")
if ($unnecessaryServices -eq 0) { Write-Host "None" }

# Display MSDTC Information
Write-Host "`nMSDTC Settings" -Fore DarkGray
Write-Host "RemoteClientAccessEnabled:" (Get-DtcNetworkSetting -DtcName Local).RemoteClientAccessEnabled
Write-Host "RemoteAdministrationAccessEnabled:" (Get-DtcNetworkSetting -DtcName Local).RemoteAdministrationAccessEnabled
Write-Host "InboundTransactionsEnabled:" (Get-DtcNetworkSetting -DtcName Local).InboundTransactionsEnabled
Write-Host "OutboundTransactionsEnabled:" (Get-DtcNetworkSetting -DtcName Local).OutboundTransactionsEnabled
Write-Host "Authentication:" (Get-DtcNetworkSetting -DtcName Local).AuthenticationLevel
Write-Host "XATransactionsEnabled:" (Get-DtcNetworkSetting -DtcName Local).XATransactionsEnabled
Write-Host "LUTransactionsEnabled:" (Get-DtcNetworkSetting -DtcName Local).LUTransactionsEnabled

# Display Windows Firewall Information
Write-Host "`nWindows Firewall Status" -fore DarkGray -NoNewLine
Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table -AutoSize

# Get and Display Application Event Log Information
Write-Host "Most Common Application Event Log Errors" -Fore DarkGray -NoNewLine
$eventLog = Get-EventLog -Log Application -EntryType Error
$eventLog | Group-Object -Property Source -NoElement | Sort-Object -Property Count -Desc | Format-Table  -AutoSize

Write-Host "BizTalk Related Application Event Log Errors" -Fore DarkGray -NoNewLine
$BizTalkEventLog = Get-Eventlog -Log Application -EntryType Error | Where-Object {$_.eventID -eq "5410" -or $_.Source -like "*BizTalk*" -or $_.Source -like "*BAM*" -or $_.Source -like "*DTC*" -or $_.Source -like "*RuleEngine*"} | Select-Object Source,EventID,Message -Unique | Sort-Object Message | Format-Table -AutoSize
$BizTalkEventLog

# Get and Display Computer Information
Write-Host "Computer Information" -fore Green
$computerDetails = Get-WmiObject Win32_ComputerSystem
$drive = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter = 'C:'"
$defragReport = $drive.DefragAnalysis()
Write-Host "File System (C:):" $drive.FileSystem
Write-Host "Capacity (C:):" ([Math]::Round(($drive.Capacity / 1024 / 1024 / 1024),0)) "GB"
Write-Host "Fragmentation (C:):" $defragReport.DefragAnalysis.FilePercentFragmentation"%"
Write-Host "Free Disk Space (C:):" $defragReport.DefragAnalysis.FreeSpacePercent"%"

Write-Host "System Type:" $computerDetails.SystemType
Write-Host "Physical RAM:" ([math]::round(($computerDetails.TotalPhysicalMemory/1GB),0))"GB"
Write-Host "Domain:" $computerDetails.Domain
Write-Host "Computer Model:" $computerDetails.model
Write-Host "Computer Manufacturer:" $computerDetails.manufacturer
Write-Host "BIOS Version:" (Get-WmiObject Win32_BIOS).BIOSVersion
Write-Host "BIOS Serial Number:" (Get-WmiObject Win32_BIOS).serialnumber

$processors = Get-WmiObject win32_processor 
if (@($processors)[0].NumberOfCores) { $cores = @($processors).count * @($processors)[0].NumberOfCores }
else { $cores = @($processors).count }
$sockets = @(@($processors) | ForEach-Object {$_.SocketDesignation} | select-object -unique).count;
    
Write-Host "`nProcessor(s) and Load Percentage" -Fore DarkGray
foreach ($processor in $processors ) { Write-Host $processor.Name "("$processor.LoadPercentage"% )" }
Write-Host "Cores: $cores, Sockets: $sockets"

Write-Host("`nAnti-virus and Security Software") -Fore DarkGray
$antiVirus = Get-WmiObject Win32_Product -Filter "name LIKE '%virus%' or name LIKE '%defend%' or name LIKE '%security%' or name LIKE '%protect%'"
if ($antiVirus.Count -gt 0) { $antiVirus.Name }
else { Write-Host "None" }

# Display Network Information
Write-Host "`nNetwork Information" -fore Green
Write-Host "TCP ports in use:" (netstat -ano -p tcp).Count
Write-Host "`nNetwork Connections" -fore DarkGray -NoNewLine
Get-NetAdapter | Select-Object Name,Status,LinkSpeed | Format-Table  -AutoSize

$nics = Get-WmiObject -computer localhost win32_networkadapterconfiguration -Filter "ipenabled='true'"
Write-Host "IP Address(es):" 
$nics.IPAddress

foreach ($nic in $nics ) {
    Write-Host "Description:" $nic.Description
    Write-Host "DHCP Server:" $nic.DHCPServer
    Write-Host "Default Gateway:" $nic.DefaultIPGateway
    Write-Host "MAC Address:" $nic.MACAddress
    Write-Host "NetBIOS over TCP/IP: " -NoNewline
    switch ($nic.TcpipNetbiosOptions) {
        0 { Write-Host "Enabled via DHCP" }
        1 { Write-Host "Enabled" }
        2 { Write-Host "Disabled" }
    }
}

Write-Host "`nInternet Download Test" -fore DarkGray
try {
    # Source download URL
    $source = "http://speedtest.newark.linode.com/100MB-newark.bin"
    
    # Destination download file
    $destination = $env:USERPROFILE + "\Downloads\Download.txt"

    # Download file
    $startDownloadTime = Get-Date
    Invoke-WebRequest $source -OutFile $destination -ErrorAction Stop
    $endDownloadTime = Get-Date
    
    $fileSize = ([Math]::Round(((Get-Item $destination).Length / 1024),0))
    $totalTime = ([Math]::Round($(($endDownloadTime-$startDownloadTime).TotalSeconds), 2))
    Write-Host "Download Time: $totalTime seconds"
    Write-Host "File Size: $fileSize KB"
    Write-Host "Download Speed:" ([Math]::Round(($fileSize / $totalTime), 2)) "KB/s"

    # Delete downloaded file
    Remove-Item $destination
}
catch {
    Write-Host "Unable to perform Internet download speed test" -fore Red
}

Write-Host "`nDomain Controller Time Sync" -fore DarkGray
try {
    Import-Module ActiveDirectory
    $DC = Get-ADDomainController -Discover -ErrorAction Stop | Select-Object -Expand HostName 
    $TimeServer = w32tm /stripchart /computer:$DC /samples:5 /dataonly
    $TimeServer
}
catch {
    Write-Host "Unable to contact Domain Controller" -fore Red
}

$endTime = Get-Date
Write-Host "`nScript processing time:" ([Math]::Round($(($endTime-$startTime).TotalMinutes), 2)) "minutes"