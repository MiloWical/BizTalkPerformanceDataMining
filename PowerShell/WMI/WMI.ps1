Param(
    [String] $ConfigFileName
)

$Config = (Get-Content $ConfigFileName) -join "`n" | ConvertFrom-Json

function InitializeHostWmiProvider()
{
    try { # Get BizTalk Information
        #WMI Interface Object
        $BizTalkWmiProvider = New-Object PSObject

        $BizTalkGroup = Get-WmiObject MSBTS_GroupSetting -namespace root\MicrosoftBizTalkServer -ErrorAction Stop 
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkGroup' -Value $BizTalkGroup         

        return $BizTalkWmiProvider;
    }
    #Use this catch block to catch initial WMI issues.
    #Technically, try/catch should be used everywhere.
    catch {
        Write-Host $_.Exception.Message;

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;
        Write-Host "BizTalk not detected on this machine, or user ($CurrentUser) not member of BizTalk Administrators group" -fore Red
        return $null;
    }
}

function ServerDetails ($Wmi)
{
    $BizTalkServer = Get-WmiObject MSBTS_Server -namespace root\MicrosoftBizTalkServer -ErrorAction Stop 
    $Wmi | Add-Member -type NoteProperty -Name 'BizTalkServer' -Value $BizTalkServer

    $BizTalkREG = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\BizTalk Server\3.0' -ErrorAction Stop
    $Wmi | Add-Member -type NoteProperty -Name 'BizTalkREG' -Value $BizTalkREG

    Write-Host "`nBizTalk Information" -fore DarkGray
    Write-Host $Wmi.BizTalkREG.ProductName "("$Wmi.BizTalkREG.ProductEdition"Edition )"
    Write-Host "Product Version:" $Wmi.BizTalkREG.ProductVersion
    Write-Host "Installation Path:" $Wmi.BizTalkREG.InstallPath
    Write-Host "Installation Date:" $Wmi.BizTalkREG.InstallDate
    Write-Host "Server name:" $Wmi.BizTalkServer.Name
    Write-Host "SSO Server:" $Wmi.BizTalkGroup.SSOServerName
    Write-Host "BizTalk Admin group:" $Wmi.BizTalkGroup.BizTalkAdministratorGroup
    Write-Host "BizTalk Operators group:" $Wmi.BizTalkGroup.BizTalkOperatorGroup
    Write-Host "BizTalk Group Name:" $Wmi.BizTalkGroup.Name
    Write-Host "Cache Refresh Interval:" $Wmi.BizTalkGroup.ConfigurationCacheRefreshInterval

    switch ($Wmi.BizTalkGroup.GlobalTrackingOption) {
        0 { Write-Host "Global Tracking: Off" }
        1 { Write-Host "Global Tracking: On" }
    }

    $Products = Get-WmiObject win32_product -ErrorAction Stop 
    $Wmi | Add-Member -type NoteProperty -Name 'Products' -Value $Products

    Write-Host "`nInstalled BizTalk Software" -Fore DarkGray
    $Wmi.Products | where-object { $_.Name -like "*BizTalk*" } | select-object Name -Unique | Sort-Object Name | Select-Object -expand Name
}

function HostInstances($Wmi)
{
    $HostInstances = Get-WmiObject MSBTS_HostInstance -namespace root\MicrosoftBizTalkServer -ErrorAction Stop 
    $Wmi | Add-Member -type NoteProperty -Name 'HostInstances' -Value $HostInstances

    Write-Host "`nHost Instance Information ("$Wmi.HostInstances.Count")" -fore DarkGray
    
    foreach ($hostInstance in $Wmi.HostInstances) {
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
                Write-Host $hostInstanceState "(Disabled:$($hostInstance.IsDisabled))" -fore Yellow
            }
            else {
                Write-Host $hostInstance.hostname "($hostInstanceType)"
            }
        }
    }

    $TrackingHost = Get-WmiObject MSBTS_Host -Namespace root\MicrosoftBizTalkServer -ErrorAction Stop  | Where-Object {$_.HostTracking -eq "true" }
    $Wmi | Add-Member -type NoteProperty -Name 'TrackingHost' -Value $TrackingHost

    Write-Host "`nTracking Host(s)" -Fore DarkGray
    $Wmi.TrackingHost.Name
}

function Applications($Wmi)
{
    Add-Type -Path ".\Microsoft.RuleEngine.dll"
    Add-Type -Path ".\Microsoft.Biztalk.RuleEngineExtensions.dll"
    Add-Type -Path ".\Microsoft.BizTalk.ExplorerOM.dll"
    [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.BizTalk.ExplorerOM")
    $BizTalkDBInstance = $Wmi.BizTalkGroup.MgmtDbServerName
    $BizTalkDB = $Wmi.BizTalkGroup.MgmtDbName

    # $Wmi | Add-Member -type NoteProperty -Name 'BizTalkDBInstance' -Value $BizTalkDBInstance
    # $Wmi | Add-Member -type NoteProperty -Name 'BizTalkDB' -Value $BizTalkDB

    $BizTalkOM = New-Object Microsoft.BizTalk.ExplorerOM.BtsCatalogExplorer
    $BizTalkOM.ConnectionString = "SERVER=$BizTalkDBInstance;DATABASE=$BizTalkDB;Integrated Security=SSPI"
    $Wmi | Add-Member -type NoteProperty -Name 'BizTalkOM' -Value $BizTalkOM

    # Get BizTalk Application Information
    $applications = $Wmi.BizTalkOM.Applications

    # Display BizTalk Application Information
    Write-Host "`nBizTalk Applications ("$applications.Count")" -fore DarkGray

    Foreach ($application in $applications) 
    {
        Write-Host $application.Name "- " -NoNewline

        if ($application.Status -eq "Started") {
            Write-Host $application.Status -fore Green
        }
        elseif ($application.Status -eq "Stopped") {
            Write-Host $application.Status -fore Red
        }
        else {
            Write-Host $application.Status -fore Yellow
        }
    }
}

function ServiceInstances($Wmi)
{
    #Service Instance Mining
    # Get BizTalk Service Instance Information
    [Array]$ReadyToRun = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 1)' -ErrorAction SilentlyContinue 
    [Array]$Active = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 2) and not(ServiceClass = 16)' -ErrorAction SilentlyContinue 
    [Array]$Dehydrated = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 8)' -ErrorAction SilentlyContinue 
    [Array]$Breakpoint = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 64)' -ErrorAction SilentlyContinue 
    [Array]$SuspendedOrchs = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 1) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue 
    [Array]$SuspendedMessages = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 4) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue 
    [Array]$SuspendedRouting = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 64)' -ErrorAction SilentlyContinue 
    [Array]$SuspendedIsolated = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 32) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue 

    $ServiceInstances = New-Object PSObject
    $ServiceInstances | Add-Member -type NoteProperty -Name 'ReadyToRun' -Value $ReadyToRun
    $ServiceInstances | Add-Member -type NoteProperty -Name 'Active' -Value $Active
    $ServiceInstances | Add-Member -type NoteProperty -Name 'Dehydrated' -Value $Dehydrated
    $ServiceInstances | Add-Member -type NoteProperty -Name 'Breakpoint' -Value $Breakpoint
    $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedOrchs' -Value $SuspendedOrchs
    $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedMessages' -Value $SuspendedMessages
    $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedRouting' -Value $SuspendedRouting
    $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedIsolated' -Value $SuspendedIsolated

    $Wmi | Add-Member -type NoteProperty -Name 'ServiceInstances' -Value $ServiceInstances

    # Display BizTalk Service Instance Information
    Write-Host "`nService Instance Information" -fore DarkGray
    Write-Host "Instances Ready to Run:" $Wmi.ServiceInstances.ReadyToRun.Count
    Write-Host "Active Instances:" $Wmi.ServiceInstances.Active.Count
    Write-Host "Dehydrated Instances:" $Wmi.ServiceInstances.Dehydrated.Count
    Write-Host "Instances in Breakpoint:" $Wmi.ServiceInstances.Breakpoint.Count
    Write-Host "Suspended Orchestrations:" $Wmi.ServiceInstances.SuspendedOrchs.Count
    Write-Host "Suspended Messages:" $Wmi.ServiceInstances.SuspendedMessages.Count
    Write-Host "Routing Failures:" $Wmi.ServiceInstances.SuspendedRouting.Count
    Write-Host "Isolated Adapter Failures:" $Wmi.ServiceInstances.SuspendedIsolated.Count
}

function ReceiveLocations($Wmi)
{
    [Array]$ReceiveLocations = Get-WmiObject MSBTS_ReceiveLocation -namespace 'root\MicrosoftBizTalkServer' -ErrorAction SilentlyContinue 
    $Wmi | Add-Member -type NoteProperty -Name 'ReceiveLocations' -Value $ReceiveLocations

    Write-Host "`nReceive Locations (" $Wmi.ReceiveLocations.Count ")" -fore DarkGray
    
    if ($Wmi.ReceiveLocations.Count -gt 0) 
    { 
        foreach($ReceiveLocation in $Wmi.ReceiveLocations)
        {
            #Uncomment to see all properties
            #$ReceiveLocation | Select-Object

            Write-Host $ReceiveLocation.Name "- " -NoNewline

            if ($ReceiveLocation.IsDisabled -eq $false) {
                Write-Host "Enabled" -fore Green
            }
            else {
                Write-Host "Disabled" -fore Red
            }

            Write-Host "`tHost: "$ReceiveLocation.HostName
            Write-Host "`tAdapter Name: "$ReceiveLocation.AdapterName
            Write-Host "`tInbound Transport URL: "$ReceiveLocation.InboundTransportUrl
        }
    }
    else { Write-Host "None" }
}

function SendPorts($Wmi)
{
    [Array]$SendPorts = Get-WmiObject MSBTS_SendPort -namespace 'root\MicrosoftBizTalkServer' -ErrorAction SilentlyContinue 
    $Wmi | Add-Member -type NoteProperty -Name 'SendPorts' -Value $SendPorts

    Write-Host "`nSend Ports (" $Wmi.SendPorts.Count ")" -fore DarkGray
    
    if ($Wmi.SendPorts.Count -gt 0) 
    { 
        foreach($SendPort in $Wmi.SendPorts)
        {
            Write-Host $SendPort.Name "- " -NoNewline
            
            switch($SendPort.Status)
            {
                1 { Write-Host "Bound" -fore Yellow }
                2 { Write-Host "Stopped" -fore Red }
                3 { Write-Host "Started" -fore Green }
            }
    
            Write-Host "`tAddress: "$SendPort.PTAddress
            Write-Host "`tTransport Type: "$SendPort.PTTransportType

            [Xml]$SendPortConfigXml = $SendPort.PTCustomCfg
    
            $CertificateThumbprint = Select-Xml -Xml $SendPortConfigXml -XPath "/CustomProps/Certificate"
    
            If(-not([System.String]::IsNullOrEmpty($CertificateThumbprint)))
            {
                Write-Host "`tCertificate Thumbprint: "$CertificateThumbprint
            }
        }
    }
    else { Write-Host "None" }

    #$Wmi.SendPorts[2] | Select-Object
}

function Orchestrations($Wmi)
{
    [Array]$Orchestrations = Get-WmiObject MSBTS_Orchestration -namespace 'root\MicrosoftBizTalkServer' -ErrorAction SilentlyContinue 
    $Wmi | Add-Member -type NoteProperty -Name 'Orchestrations' -Value $Orchestrations

    Write-Host "`nOrchestrations (" $Wmi.Orchestrations.Count ")" -fore DarkGray
    
    If ($Wmi.Orchestrations.Count -gt 0) 
    { 
        foreach($Orchestration in $Wmi.Orchestrations)
        {
            Write-Host $Orchestration.Name "- " -NoNewline

            Switch($Orchestration.OrchestrationStatus)
            {
                1 { Write-Host "Unbound" -fore White }
                2 { Write-Host "Bound" -fore Yellow }
                3 { Write-Host "Stopped" -fore Red }
                4 { Write-Host "Started" -fore Green }
            }
        }
    }
    Else { Write-Host "None" }
}

function MSDTC($Wmi)
{
    # Display MSDTC Information
    Write-Host "`nMSDTC Settings" -fore DarkGray

    $DTC = New-Object PSObject

    $RemoteClientAccessEnabled = (Get-DtcNetworkSetting -DtcName Local).RemoteClientAccessEnabled
    $DTC | Add-Member -type NoteProperty -Name 'RemoteClientAccessEnabled' -Value $RemoteClientAccessEnabled
    Write-Host "RemoteClientAccessEnabled:" $RemoteClientAccessEnabled
    
    $RemoteAdministrationAccessEnabled = (Get-DtcNetworkSetting -DtcName Local).RemoteAdministrationAccessEnabled
    $DTC | Add-Member -type NoteProperty -Name 'RemoteAdministrationAccessEnabled' -Value $RemoteAdministrationAccessEnabled
    Write-Host "RemoteAdministrationAccessEnabled:" $RemoteAdministrationAccessEnabled
    
    $InboundTransactionsEnabled = (Get-DtcNetworkSetting -DtcName Local).InboundTransactionsEnabled
    $DTC | Add-Member -type NoteProperty -Name 'InboundTransactionsEnabled' -Value $InboundTransactionsEnabled
    Write-Host "InboundTransactionsEnabled:" $InboundTransactionsEnabled
    
    $OutboundTransactionsEnabled = (Get-DtcNetworkSetting -DtcName Local).OutboundTransactionsEnabled
    $DTC | Add-Member -type NoteProperty -Name 'OutboundTransactionsEnabled' -Value $OutboundTransactionsEnabled
    Write-Host "OutboundTransactionsEnabled:" $OutboundTransactionsEnabled
    
    $Authentication = (Get-DtcNetworkSetting -DtcName Local).AuthenticationLevel
    $DTC | Add-Member -type NoteProperty -Name 'AuthenticationLevel' -Value $AuthenticationLevel
    Write-Host "Authentication:" $Authentication
    
    $XATransactionsEnabled = (Get-DtcNetworkSetting -DtcName Local).XATransactionsEnabled
    $DTC | Add-Member -type NoteProperty -Name 'XATransactionsEnabled' -Value $XATransactionsEnabled
    Write-Host "XATransactionsEnabled:" $XATransactionsEnabled
    
    $LUTransactionsEnabled = (Get-DtcNetworkSetting -DtcName Local).LUTransactionsEnabled
    $DTC | Add-Member -type NoteProperty -Name 'LUTransactionsEnabled' -Value $LUTransactionsEnabled
    Write-Host "LUTransactionsEnabled:" $LUTransactionsEnabled

    $Wmi | Add-Member -type NoteProperty -Name 'DTC' -Value $DTC
}

function Network($Wmi)
{
    Write-Host "`nNetwork Information" -fore Green
    Write-Host "TCP ports in use:" (netstat -ano -p tcp).Count
    Write-Host "`nNetwork Connections" -fore DarkGray -NoNewLine
    Get-NetAdapter | Select-Object Name,Status,LinkSpeed | Format-Table  -AutoSize
    
    $NICs = Get-WmiObject -computer localhost win32_networkadapterconfiguration -Filter "ipenabled='true'"

    $Wmi | Add-Member -type NoteProperty -Name 'NICs' -Value $NICs

    Write-Host "IP Address(es):" 
    $Wmi.NICs.IPAddress
    
    foreach ($NIC in $Wmi.NICs ) {
        Write-Host "`nDescription:" $NIC.Description
        Write-Host "DHCP Server:" $NIC.DHCPServer
        Write-Host "Default Gateway:" $NIC.DefaultIPGateway
        Write-Host "MAC Address:" $NIC.MACAddress
        Write-Host "NetBIOS over TCP/IP: " -NoNewline
        switch ($NIC.TcpipNetbiosOptions) {
            0 { Write-Host "Enabled via DHCP" }
            1 { Write-Host "Enabled" }
            2 { Write-Host "Disabled" }
        }
    }
}

function ProcessConfiguration ($configurationType, $Wmi)
{
    switch ($configurationType) {
        "ServerDetails" { ServerDetails($Wmi)  }
        "HostInstances" { HostInstances($Wmi)  }
        "Applications" { Applications($Wmi)  }
        "ServiceInstances" { ServiceInstances($Wmi)  }
        "ReceiveLocations" { ReceiveLocations($Wmi) }
        "SendPorts" { SendPorts($Wmi) }
        "Orchestrations" { Orchestrations($Wmi) }
        "MSDTC" { MSDTC($Wmi) }
        "Network" { Network($Wmi) }
        Default { Write-Host "Invalid configuration type: $configurationType" -fore Red}
    } 
}

$WmiInterface = InitializeHostWmiProvider

If($null -eq $WmiInterface)
{
    return;
}

foreach($config in $Config.Configurations)
{
    ProcessConfiguration $config $WmiInterface #Syntax looks weird, but this is how it's done.
}



