$Config = (Get-Content ".\WMI.config") -join "`n" | ConvertFrom-Json

$HostName = [System.String]::Empty;

function LoadHostWmiProviders()
{
    try { # Get BizTalk Information
        $BizTalkGroup = Get-WmiObject MSBTS_GroupSetting -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
        $BizTalkMsgBoxDb = Get-WmiObject MSBTS_MsgBoxSetting -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
        $BizTalkServer = Get-WmiObject MSBTS_Server -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
               
        #$registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $HostName).OpenSubKey("SOFTWARE\Microsoft\BizTalk Server\3.0")
        #$BizTalkREG = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $HostName).OpenSubKey("SOFTWARE\Microsoft\BizTalk Server\3.0") | Get-ItemProperty -ErrorAction Stop
        $BizTalkREG = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\BizTalk Server\3.0' -ErrorAction Stop
        
        $HostInstances = Get-WmiObject MSBTS_HostInstance -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
        $TrackingHost = Get-WmiObject MSBTS_Host -Namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName | Where-Object {$_.HostTracking -eq "true" }        

        Add-Type -Path ".\Microsoft.RuleEngine.dll"
        Add-Type -Path ".\Microsoft.Biztalk.RuleEngineExtensions.dll"
        Add-Type -Path ".\Microsoft.BizTalk.ExplorerOM.dll"
        [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.BizTalk.ExplorerOM")
        $BizTalkDBInstance = $BizTalkGroup.MgmtDbServerName
        $BizTalkDB = $BizTalkGroup.MgmtDbName

        $BizTalkOM = New-Object Microsoft.BizTalk.ExplorerOM.BtsCatalogExplorer
        $BizTalkOM.ConnectionString = "SERVER=$BizTalkDBInstance;DATABASE=$BizTalkDB;Integrated Security=SSPI"
        
        $Products = Get-WmiObject win32_product -ErrorAction Stop -ComputerName $HostName

        #Service Instance Mining
        # Get BizTalk Service Instance Information
        [Array]$ReadyToRun = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 1)' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$Active = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 2) and not(ServiceClass = 16)' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$Dehydrated = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 8)' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$Breakpoint = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceStatus = 64)' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$SuspendedOrchs = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 1) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$SuspendedMessages = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 4) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$SuspendedRouting = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 64)' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$SuspendedIsolated = Get-WmiObject MSBTS_ServiceInstance -namespace 'root\MicrosoftBizTalkServer' -filter '(ServiceClass = 32) and (ServiceStatus = 4 or ServiceStatus = 32)' -ErrorAction SilentlyContinue -ComputerName $HostName

        $ServiceInstances = New-Object PSObject
        $ServiceInstances | Add-Member -type NoteProperty -Name 'ReadyToRun' -Value $ReadyToRun
        $ServiceInstances | Add-Member -type NoteProperty -Name 'Active' -Value $Active
        $ServiceInstances | Add-Member -type NoteProperty -Name 'Dehydrated' -Value $Dehydrated
        $ServiceInstances | Add-Member -type NoteProperty -Name 'Breakpoint' -Value $Breakpoint
        $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedOrchs' -Value $SuspendedOrchs
        $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedMessages' -Value $SuspendedMessages
        $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedRouting' -Value $SuspendedRouting
        $ServiceInstances | Add-Member -type NoteProperty -Name 'SuspendedIsolated' -Value $SuspendedIsolated

        [Array]$ReceiveLocations = Get-WmiObject MSBTS_ReceiveLocation -namespace 'root\MicrosoftBizTalkServer' -ErrorAction SilentlyContinue -ComputerName $HostName
        [Array]$SendPorts = Get-WmiObject MSBTS_SendPort -namespace 'root\MicrosoftBizTalkServer' -ErrorAction SilentlyContinue -ComputerName $HostName

        #WMI Interface Object
        $BizTalkWmiProvider = New-Object PSObject
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkGroup' -Value $BizTalkGroup
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkMsgBoxDb' -Value $BizTalkMsgBoxDb
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkServer' -Value $BizTalkServer
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkREG' -Value $BizTalkREG
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'HostInstances' -Value $HostInstances
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'TrackingHost' -Value $TrackingHost
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkDBInstance' -Value $BizTalkDBInstance
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkDB' -Value $BizTalkDB
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkOM' -Value $BizTalkOM
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'Products' -Value $Products
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'ServiceInstances' -Value $ServiceInstances
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'ReceiveLocations' -Value $ReceiveLocations
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'SendPorts' -Value $SendPorts

        return $BizTalkWmiProvider;
    }
    catch {
        Write-Host $_.Exception.Message;

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;
        Write-Host "${HostName}: BizTalk not detected on this machine, or user ($CurrentUser) not member of BizTalk Administrators group" -fore Red
        return $null;
    }
}

function ServerDetails ($Wmi)
{
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
    Write-Host "`nInstalled BizTalk Software" -Fore DarkGray
    $Wmi.Products | where-object { $_.Name -like "*BizTalk*" } | select-object Name -Unique | Sort-Object Name | Select-Object -expand Name
}

function HostInstances($Wmi)
{
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
                Write-Host $hostInstanceState "(Disabled:$($hostInstance.IsDisabled))" -fore DarkYellow
            }
            else {
                Write-Host $hostInstance.hostname "($hostInstanceType)"
            }
        }
    }
    Write-Host "`nTracking Host(s)" -Fore DarkGray
    $Wmi.TrackingHost.Name
}

function Applications($Wmi)
{
    # Get BizTalk Application Information
    $applications = $Wmi.BizTalkOM.Applications

    # Display BizTalk Application Information
    Write-Host "`nBizTalk Applications ("$applications.Count")" -fore DarkGray

    Foreach ($application in $applications) 
    {
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
}

function ServiceInstances($Wmi)
{
    # Display BizTalk Service Instance Information
Write-Host "`nService Instance Information" -fore DarkGray
Write-Host "Instances Ready to Run:" $Wmi.ServiceInstances.ReadyToRun.Count
Write-Host "Active Instances:" $Wmi.ServiceInstances.Active.Count
Write-Host "Dehydrated Instances:" $Wmi.ServiceInstances.Dehydrated.Count
Write-Host "Instances in Breakpoint:" $Wmi.ServiceInstances.Breakpoint.Count
Write-Host "Suspended Orchestrations:" $Wmi.ServiceInstances.SuspendedOrchs.count
Write-Host "Suspended Messages:" $Wmi.ServiceInstances.SuspendedMessages.count
Write-Host "Routing Failures:" $Wmi.ServiceInstances.SuspendedRouting.count
Write-Host "Isolated Adapter Failures:" $Wmi.ServiceInstances.SuspendedIsolated.count
}

function ReceiveLocations($Wmi)
{
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

function ProcessConfiguration ($configurationType, $Wmi)
{
    switch ($configurationType) {
        "ServerDetails" { ServerDetails($Wmi)  }
        "HostInstances" { HostInstances($Wmi)  }
        "Applications" { Applications($Wmi)  }
        "ServiceInstances" { ServiceInstances($Wmi)  }
        "ReceiveLocations" { ReceiveLocations($Wmi) }
        "SendPorts" { SendPorts($Wmi) }
        Default { Write-Host "Invalid configuration type: $configurationType" -fore Red}
    } 
}

function ReadConfigurationData ($HostConfiguration) 
{
    $HostName = $HostConfiguration.Name;

    $WmiInterface = LoadHostWmiProviders($HostName);

    If($null -eq $WmiInterface)
    {
        return;
    }

    Write-Host "${HostName}: BizTalk WMI providers loaded successfully." -fore Green

    foreach($config in $HostConfiguration.Configurations)
    {
        ProcessConfiguration $config $WmiInterface #Syntax looks weird, but this is how it's done.
    }
}

foreach($BizTalkHost in $Config.Hosts)
{
    ReadConfigurationData($BizTalkHost);
}




