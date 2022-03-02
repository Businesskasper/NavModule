#Requires -RunAsAdministrator

<#
Fragt die Registry nach installierten NAV Komponenten ab.
#>
function GetNavInstallations() {

    $navInstallations = @{}
    $i = 0
    $navKeys = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Microsoft Dynamics NAV" | ? { [int]::TryParse($_.PSChildName, [ref]$i) -and $i -ge 100 }

    foreach ($navKey in $navKeys) {
        
        $service = Get-ItemProperty -Path ([System.IO.Path]::Combine($navKey.PSPath, "Service")) -ErrorAction SilentlyContinue | select Installed, Path
        $webClient = Get-ItemProperty -Path ([System.IO.Path]::Combine($navKey.PSPath, "Web Client")) -ErrorAction SilentlyContinue | select Installed, Path
        $windowsClientPath = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{00000000-0000-0$($navKey.PSChildName)-0000-0CE90DA3512B}" -ErrorAction SilentlyContinue | select -ExpandProperty InstallLocation


        $navInstallations[$navKey.PSChildName] = [PSCustomObject]@{
            Version                = $navKey.PSChildName
            ServicePath            = $service.Path
            ServiceInstalled       = $service.Installed -and -not ([String]::IsNullOrWhiteSpace($service.Path)) -and (Test-Path -Path $service.Path)
            WebClientPath          = $webClient.Path
            WebClientInstalled     = $webClient.Installed -and -not ([String]::IsNullOrWhiteSpace($webClient.Path)) -and (Test-Path -Path $webClient.Path)
            WindowsClientPath      = $windowsClientPath
            WindowsClientInstalled = -not [String]::IsNullOrWhiteSpace($windowsClientPath) -and (Test-Path -Path $windowsClientPath)
            Modules                = @()
        }

        $modulesToCheck = @()
        if ($navInstallations[$navKey.PSChildName].ServiceInstalled) {

            $modulesToCheck += [System.IO.Path]::Combine($navInstallations[$navKey.PSChildName].ServicePath, 'Microsoft.Dynamics.Nav.Management.psm1')
            $modulesToCheck += [System.IO.Path]::Combine($navInstallations[$navKey.PSChildName].ServicePath, 'Microsoft.Dynamics.Nav.Ide.psm1')
            $modulesToCheck += [System.IO.Path]::Combine($navInstallations[$navKey.PSChildName].ServicePath, 'Microsoft.Dynamics.Nav.Apps.Management.psd1')
        }
        if ($navInstallations[$navKey.PSChildName].WebClientInstalled) {

            $modulesToCheck += [System.IO.Path]::Combine($navInstallations[$navKey.PSChildName].WebClientPath, 'Modules', 'NAVWebClientManagement', 'NAVWebClientManagement.psm1')
        }

        foreach ($moduleToCheck in $modulesToCheck) {

            if (Test-Path -Path $moduleToCheck) {

                $navInstallations[$navKey.PSChildName].Modules += $moduleToCheck
            }
        }
    }

    return $navInstallations
}


<#
Bereitet einen Powershell InitialSessionState mit den korrekten NAV Modulen vor.
#>
function GetInitialSessionState([string]$Version) {

    $navInstallations = GetNavInstallations
    $navModulesToImport = @()
    $navModulesToImport += $navInstallations[$Version].Modules

    $initialSessionState = [InitialSessionState]::CreateDefault()
    $initialSessionState.ImportPSModule($navModulesToImport)

    if ($navInstallations[$Version].WindowsClientInstalled) {

        $FinSqlExeFile = [System.IO.Path]::Combine($navInstallations[$Version].WindowsClientPath, 'finsql.exe')
        $NavIde = [System.IO.Path]::Combine($navInstallations[$Version].WindowsClientPath, 'finsql.exe')

        $initialSessionState.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("FinSqlExeFile", $FinSqlExeFile, ""))
        $initialSessionState.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("NavIde", $NavIde, ""))
    }
    
    return $initialSessionState
}


<#
Bereitet einen Powershell Runspace mit Skript Block, Parametern und einem InitialSessionState vor.
#>
function GetPSInstance([ScriptBlock]$Code, [Hashtable]$ScriptParams, [string]$Version) {

    $runspace = [runspacefactory]::CreateRunspace((NavModule\GetInitialSessionState -Version $Version))
    $runspace.ApartmentState = "STA"
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.Open()

    $instance = [powershell]::Create()
    $instance.AddScript($Code) | Out-Null

    foreach ($key in $ScriptParams.Keys) {
        
        $instance.AddParameter($key, $ScriptParams[$key]) | Out-Null
    }
    
    $instance.Runspace = $runspace

    return $instance
}


<#
Führt eine vorbereitete Powershell Instanz aus und spiegelt die Ergebnisse und Streams nach außen.
#>
function InvokePSInstance([powershell]$Instance, [switch]$Verbose, [boolean]$HideLicenseWarning = $true, [boolean]$HideRestartWarning = $true, [array]$MessagesToHide = @()) {
    
    try {
        if ($null -eq $MessagesToHide) {

            $MessagesToHide = @()
        }
        if ($null -eq $global:hiddenMessages) {

            $global:hiddenMessages = @{}
        }
        if ($HideLicenseWarning) {

            $MessagesToHide += @(
                "*Diese Lizenz ist mit dieser Version von Business Central nicht kompatibel.*", 
                "*This license is not compatible with this version of Business Central.*",
                "*The setup of users is in violation of the license. The license allows*",
                "*Caution: Your program license expires in*",
                "*Lizenz*läuft*ab*"
            )
        }
        if ($HideRestartWarning) {

            $MessagesToHide += @(
                "*The new settings value will not take effect until you stop and restart the service.*", 
                "*Consider using '-ApplyTo All' in the command to apply new setting value without having to restart the server instance.*",
                "*The new settings value will not take effect until you stop and restart the service.*",
                "*Importing a license file requires a restart of other services using the same database.*"
            )
        }

        $global:hiddenMessages[$instance.InstanceId.Guid] = $MessagesToHide

        if ($Verbose) {

            $Instance.Streams.Verbose.add_DataAdded( {
      
                    Param (
                        [Object]$sender,
                        [System.Management.Automation.DataAddedEventArgs]$e
                    )

                    $runspaceId = $e.PowerShellInstanceId.Guid
                    $entries = $sender.ReadAll()

                    foreach ($entry in $entries) {
                    
                        $hide = $false
                        foreach ($messageToHide in $global:hiddenMessages[$runspaceId]) {

                            if ($entry -like $messageToHide) {

                                $hide = $true
                            }
                        }

                        if (-not $hide) {

                            Write-Verbose ($entry | Out-String)
                        }
                    }
                })

            $Instance.Streams.Debug.add_DataAdded( {
      
                    Param (
                        [Object]$sender,
                        [System.Management.Automation.DataAddedEventArgs]$e
                    )

                    $runspaceId = $e.PowerShellInstanceId.Guid
                    $entries = $sender.ReadAll()

                    foreach ($entry in $entries) {

                        $hide = $false
                        foreach ($messageToHide in $global:hiddenMessages[$runspaceId]) {

                            if ($entry -like $messageToHide) {

                                $hide = $true
                            }
                        }

                        if (-not $hide) {

                            Write-Debug ($entry | Out-String)
                        }
                    }
                })
        }

        $Instance.Streams.Information.add_DataAdded( {
      
                Param (
                    [Object]$sender,
                    [System.Management.Automation.DataAddedEventArgs]$e
                )

                $runspaceId = $e.PowerShellInstanceId.Guid
                $entries = $sender.ReadAll()

                foreach ($entry in $entries) {

                    $hide = $false
                    foreach ($messageToHide in $global:hiddenMessages[$runspaceId]) {

                        if ($entry -like $messageToHide) {

                            $hide = $true
                        }
                    }

                    if (-not $hide) {

                        Write-Host ($entry | Out-String)
                    }
                }
            })

        $Instance.Streams.Warning.add_DataAdded( {
      
                Param (
                    [Object]$sender,
                    [System.Management.Automation.DataAddedEventArgs]$e
                )

                $runspaceId = $e.PowerShellInstanceId.Guid
                $entries = $sender.ReadAll()

                foreach ($entry in $entries) {

                    $hide = $false
                    foreach ($messageToHide in $global:hiddenMessages[$runspaceId]) {

                        if ($entry -like $messageToHide) {

                            $hide = $true
                        }
                    }

                    if (-not $hide) {

                        Write-Host $entry.ToString() -ForegroundColor Yellow
                    }
                }
            })
                
        $Instance.Streams.Error.add_DataAdded( {
      
                Param (
                    [Object]$sender,
                    [System.Management.Automation.DataAddedEventArgs]$e
                )

                $errs = $sender.ReadAll()

                foreach ($err in $errs) {

                    throw $err.Exception
                }
            })
            
        $thread = $Instance.BeginInvoke()

        do {
            #Start-Sleep -Milliseconds 500
            #start-process -FilePath cmd.exe -ArgumentList @("/c", "ping", "127.0.0.1", "-n", "6") -Wait -WindowStyle Hidden
        }
        until ($thread.IsCompleted)

        $Instance.EndInvoke($thread)
    }
    catch [Exception] {

        throw $_.Exception
    }
    finally {
        
        try {
        
            if ($Instance.InvocationStateInfo.State -eq [System.Management.Automation.PSInvocationState]::Running ) {

                $Instance.EndInvoke($thread)
            }
            if ($Instance.Runspace.RunspaceStateInfo.State -notin @([System.Management.Automation.Runspaces.RunspaceState]::Closed, [System.Management.Automation.Runspaces.RunspaceState]::Closing)) {

                $Instance.Runspace.Dispose()
                $Instance.Dispose()
            }
        }
        catch {}

    }
}


<#
Ruft die Version einer NAV Instanz ab.
#>
function GetInstanceNavVersion([string]$InstanceName) {
    
    $installedServiceTiers = (NavModule\GetNavInstallations).Values | ? { $_.ServiceInstalled }
    $instanceService = Get-WmiObject win32_service | ? { $_.Name -eq "MicrosoftDynamicsNavServer`$$($InstanceName)" } | select Name, PathName

    if ($instanceService -eq $null) {

        throw [Exception]::new("Kein Service für $($instanceName) gefunden")
    }
    elseif ($instanceService.Count -gt 1) {

        throw [Exception]::new("Mehr als ein Service für $($InstanceName) gefunden")
    }

    $servicePath = Split-Path -Path $instanceService.PathName.Split('$')[0].Trim(' ').Trim('"') -Parent
        
    return ([array]$installedServiceTiers).Where({ $_.ServicePath -eq $servicePath + "\" })[0].Version
}


<#
Erstellt eine neue NAV Instanz. 
UseSpecificPorts -> Die angegebenen Ports verwenden. Es wird trotzdem überprüft, ob die Ports noch frei sind.
UseNextFreePorts -> Die verwendeten Ports auslesen und die nächsten 5 am Stück freien Ports verwenden.
#>
function NewNavInstance {

    param(

        [string]$InstanceName, 
        
        [string] $DatabaseServerInstance,  
        
        [string] $DatabaseName, 
        
        [Parameter(ParameterSetName = "UseNextFreePorts")]
        [switch] $UseNextFreePorts,

        [Parameter(Mandatory = $true, ParameterSetName = "UseSpecificPorts")]
        [int32] $ClientPort,

        [Parameter(Mandatory = $true, ParameterSetName = "UseSpecificPorts")]
        [int32] $ManagementPort,

        [Parameter(Mandatory = $true, ParameterSetName = "UseSpecificPorts")]
        [int32] $ODataPort,

        [Parameter(Mandatory = $true, ParameterSetName = "UseSpecificPorts")]
        [int32] $SOAPPort,

        [ValidateSet("100", "140", "170", "180")]
        [string] $Version, 

        [Parameter(Mandatory = $true, ParameterSetName = "UseSpecificPorts")]
        [int32] $DeveloperPort = $null,
        
        [PSCredential] $ServiceUserCredentials, 

        [PSCredential] $SQLServerCredentials = $null, 

        [SecureString] $SqlEncryptionKeyPassword = $null,

        [Hashtable] $Configuration = $null
    )


    # Prüfen ob die Datenbank erreichbar ist
    if (-not (SqlModule\IsDatabasePresent -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName)) {

        throw [Exception]::new("Fehler bei Verbindung mit Datenbank $($DatabaseName) auf $($DatabaseServerInstance)")   
    }

    # Verwendete Ports auslesen
    $usedPorts = Get-NetTCPConnection | select -ExpandProperty LocalPort 
    
    NavModule\GetNavInstances | % {

        $usedPorts += [int32]$_.ClientPort
        $usedPorts += [int32]$_.DeveloperPort
        $usedPorts += [int32]$_.ManagementPort
        $usedPorts += [int32]$_.ODataPort
        $usedPorts += [int32]$_.SOAPPort
    }

    
    if ($PSCmdlet.ParameterSetName -eq "UseSpecificPorts") {

        <# Abprüfen ob Ports bereits in Verwendung sind
        if ($ClientPort -in $usedPorts) {
               
            throw [Exception]::new("Client Port $($ClientPort) ist bereits in Verwendung")
            return $null
        } 
        if ($ManagementPort -in $usedPorts) {
               
            throw [Exception]::new("Management Port $($ManagementPort) ist bereits in Verwendung")
            return $null
        }
        if ($DeveloperPort -in $usedPorts) {
               
            throw [Exception]::new("Developer Port $($DeveloperPort) ist bereits in Verwendung")
            return $null
        }
        if ($SOAPPort -in $usedPorts) {
               
            throw [Exception]::new("SOAP Port $($SOAPPort) ist bereits in Verwendung")
            return $null
        }
        if ($ODataPort -in $usedPorts) {
               
            throw [Exception]::new("OData Port $($ODataPort) ist bereits in Verwendung")
            return $null
        }#>
    }
    else {

        # Start sollte immer 7045 sein
        if ($usedPorts -notcontains 7045) {

            $usedPorts += 7045
        }

        # Nächste freie Ports verwenden, wenn Ports nicht angegeben sind
        $usedPorts = $usedPorts | Sort-Object 
        $lastUsedPort = 0

        $startingIndex = $usedPorts.IndexOf(7045)

        for ($i = $startingIndex; $i -le $usedPorts[$usedPorts.Length - 1]; $i++) { 

            1..5 | % {

                if (($usedPorts[$i] + $_) -in $usedPorts) {
        
                    continue
                }
            }

            $lastUsedPort = $usedPorts[$i]
            break
        }

        [int32]$ClientPort = $lastUsedPort + 2
        [int32]$ManagementPort = $lastUsedPort + 4
        [int32]$SOAPPort = $lastUsedPort + 3
        [int32]$ODataPort = $lastUsedPort + 1
        [int32]$DeveloperPort = $lastUsedPort + 5
    }

    $code = {

        param(

            [string]$InstanceName,
            [string]$DatabaseServerInstance,
            [string]$DatabaseName,
            [PSCredential]$ServiceUserCredentials,
            [string]$Version,
            [int32]$ManagementPort,
            [int32]$ClientPort,
            [int32]$ODataPort,
            [int32]$SOAPPort,
            [int32]$DeveloperPort = $null,
            [PSCredential]$SqlServerCredentials = $null,
            [SecureString]$SqlEncryptionKeyPassword = $null,
            [Hashtable]$Configuration = $null
        )

        # Instanz erstellen
        $p = @{

            ServerInstance           = $InstanceName
            ManagementServicesPort   = $ManagementPort
            ClientServicesPort       = $ClientPort
            ODataServicesPort        = $ODataPort
            SOAPServicesPort         = $SOAPPort
            ServiceAccount           = "User"
            ServiceAccountCredential = $ServiceUserCredentials
            DatabaseName             = $DatabaseName
        }

        $p["DatabaseServer"] = $DatabaseServerInstance.Split("\")[0].Trim()
        if ($DatabaseServerInstance.Split("\").Count -eq 2) {

            $p["DatabaseInstance"] = $DatabaseServerInstance.Split("\")[1].Trim()
        }

        if ($Version -ne "100") {

            $p["DeveloperServicesPort"] = $DeveloperPort   
        }

        New-NAVServerInstance @p

        if ($null -ne $SqlServerCredentials -and $null -ne $SqlEncryptionKeyPassword) {

            $keyPath = "C:\Windows\Temp\$($InstanceName).key"
            Remove-Item -Path $keyPath -Force -ErrorAction SilentlyContinue
            New-NAVEncryptionKey -KeyPath $keyPath -Password $SqlEncryptionKeyPassword -Force | Out-Null

            try {

                Import-NAVEncryptionKey -ServerInstance $InstanceName `
                    -KeyPath $keyPath `
                    -Password $SqlEncryptionKeyPassword `
                    -ApplicationDatabaseServer $DatabaseServerInstance -ApplicationDatabaseName $DatabaseName -ApplicationDatabaseCredentials $SqlServerCredentials `
                    -Force -ErrorAction Stop
            }
            catch [Exception] {

                throw
            }
            finally {

                Remove-Item -Path $keyPath -Force -ErrorAction SilentlyContinue
            }

            Set-NAVServerConfiguration -ServerInstance $InstanceName -KeyName "EnableSqlConnectionEncryption" -KeyValue "true" -WarningAction SilentlyContinue -ErrorAction Stop
            Set-NAVServerConfiguration -ServerInstance $InstanceName -KeyName "TrustSQLServerCertificate" -KeyValue "true" -WarningAction SilentlyContinue -ErrorAction Stop
            Set-NAVServerConfiguration -ServerInstance $InstanceName -DatabaseCredentials $SqlServerCredentials -Force -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        }

        # Instanz konfigurieren
        if ($null -eq $Configuration) {

            $Configuration = [hashtable]@{}
        }

        if ($Version -eq "100") {

            $Configuration["MetadataProviderCacheSize"] = "15000"
        }

        foreach ($key in $Configuration.Keys) {
                
            try {
                
                #Write-Host "Setze $($key) -> $($Configuration[$key])"
                Set-NAVServerConfiguration -ServerInstance $InstanceName -KeyName $key -KeyValue $Configuration[$key] -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
            catch [Exception] {

                Write-Host -ForegroundColor Red "Fehlgeschlagen mit `"$($_.Exception.Message)`""
            }
        }

        # Instanz neustarten
        try {

            Set-NAVServerInstance -ServerInstance $InstanceName -Start -Force -ErrorAction Stop
        }
        catch [Exception] {

            # Manchmal brauchts a bissl länger
            Start-Sleep -Seconds 30
            Set-NAVServerInstance -ServerInstance $InstanceName -Start -Force -ErrorAction Stop
        }
    }

    [hashtable]$params = @{

        InstanceName             = $InstanceName
        DatabaseServerInstance   = $DatabaseServerInstance
        DatabaseName             = $DatabaseName
        ServiceUserCredentials   = $ServiceUserCredentials
        Version                  = $Version
        ManagementPort           = $ManagementPort
        ClientPort               = $ClientPort
        ODataPort                = $ODataPort
        SOAPPort                 = $SOAPPort
        DeveloperPort            = $DeveloperPort
        SqlServerCredentials     = $SQLServerCredentials
        SqlEncryptionKeyPassword = $SqlEncryptionKeyPassword
        Configuration            = $Configuration
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version $Version

    try {

        NavModule\InvokePSInstance -Instance $psInstance

        return (NavModule\GetNavInstances -InstanceName $InstanceName | select -First 1)
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Erstellen der Instanz `"$($InstanceName)`":`n$($_.Exception.Message)", $_.Exception)
    }
} 


function SetNavInstanceConfiguration([string]$InstanceName, [string]$KeyName, [string]$KeyValue) {

    $code = {

        param (

            [string] $InstanceName,
            [string] $KeyName,
            [string] $KeyValue
        )

        Set-NAVServerConfiguration -ServerInstance $InstanceName -KeyName $KeyName -KeyValue $KeyValue -Force -WarningAction SilentlyContinue
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName 
        KeyName      = $KeyName
        KeyValue     = $KeyValue
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Konfigurieren der Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }  
}


<#
Ruft alle NAV Instanzen inklusive Web Clients ab. Kann per "-InstanceName" auf eine einzelne Instanz gefiltert werden.
#>
function GetNavInstances([string]$InstanceName = $null) {

    $syncHash = [hashtable]::Synchronized(@{

            Services = @()
            Result   = @()
        })

    $installedServiceTiers = (NavModule\GetNavInstallations).Values | ? { $_.ServiceInstalled }
    $instances = @()
    
    if ([String]::IsNullOrEmpty($InstanceName)) {

        $services = Get-WmiObject win32_service | ? { $_.Name -like 'MicrosoftDynamicsNavServer$*' } | select Name, PathName
    }
    else {

        $services = Get-WmiObject win32_service | ? { $_.Name -eq "MicrosoftDynamicsNavServer`$$($InstanceName)" } | select Name, PathName
    }

    foreach ($service in $services) {
    
        $servicePath = Split-Path -Path $service.PathName.Split('$')[0].Trim(' ').Trim('"') -Parent
        $serviceVersion = ([array]$installedServiceTiers).Where( { $_.ServicePath -eq $servicePath + "\" })[0].Version
        $instances += [PSCustomObject]@{

            Name    = $service.Name.Split('$')[1]
            Version = $serviceVersion
        }
    }

    $webInstances = NavModule\GetWebServerInstances 

    $code = {

        param (
            [Hashtable]$SyncHash,
            [string]$Version,
            [PSCustomObject[]]$WebInstances
        )
        
        foreach ($instanceName in $SyncHash.Services) {
        
            try {
                
                $configuration = Get-NAVServerConfiguration -ServerInstance $($instanceName) -ErrorAction Stop
                
                $managementPort = $configuration.Where( { $_.key -eq "ManagementServicesPort" }).Value
                $clientPort = $configuration.Where( { $_.key -eq "ClientServicesPort" }).Value
                $webClients = $WebInstances | ? { $_.ManagementServicesPort -eq $managementPort -and $_.ClientServicesPort -eq $clientPort -and $_.ServerInstance -eq $instanceName } 
                $SyncHash.Result += [PSCustomObject]@{

                    NavServerName          = $env:COMPUTERNAME.ToLower() + "." + $env:USERDNSDOMAIN.ToLower()
                    InstanceName           = $instanceName
                    Version                = $Version
                    ClientPort             = $clientPort
                    ManagementPort         = $managementPort
                    DeveloperPort          = $configuration.Where( { $_.key -eq "DeveloperServicesPort" }).Value
                    ODataPort              = $configuration.Where( { $_.key -eq "ODataServicesPort" }).Value
                    SOAPPort               = $configuration.Where( { $_.key -eq "SOAPServicesPort" }).Value
                    DatabaseServerName     = $configuration.Where( { $_.key -eq "DatabaseServer" }).Value
                    DatabaseServerInstance = $configuration.Where( { $_.key -eq "DatabaseInstance" }).Value
                    DatabaseName           = $configuration.Where( { $_.key -eq "DatabaseName" }).Value
                    WebClients             = $webClients
                }                 
            }
            catch [Exception] {
                
                throw [Exception]::new("Konnte keine Informationen für $($instanceName) abrufen.`n$($_.Exception.Message)", $_.Exception)
            }     
        } 

    }

    $instancesByVersion = $instances.Where( { $_.Version -ne $null } ) | Group-Object Version
    
    foreach ($groupedInstances in $instancesByVersion) {

        $syncHash.Services = $groupedInstances.Group | select -ExpandProperty Name
        $params = [hashtable]@{

            SyncHash     = $syncHash
            Version      = $groupedInstances.Group[0].Version
            WebInstances = $webInstances
        }

        $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version $groupedInstances.Group[0].Version

        try {
            
            NavModule\InvokePSInstance -Instance $psInstance
        }
        catch [Exception] {

            throw [Exception]::new("Fehler beim Informationsabruf installierter $($groupedInstances.Group[0].Version) Instanzen`n$($_.Exception.Message)", $_.Exception)
        }
    }
        
    return $syncHash.Result
}


function RemoveServerInstance([string]$InstanceName) {
       
    $code = {

        param (

            [string]$InstanceName
        )

        Set-NAVServerInstance -ServerInstance $InstanceName -Stop -Force -Confirm:$false -ErrorAction Stop
        Remove-NAVServerInstance -ServerInstance $InstanceName -Force -Confirm:$false -ErrorAction Stop
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Entfernen der Instanz `"$($InstanceName)`":`n$($_.Exception.Message)", $_.Exception)
    }
}


function RestartNavServerInstance([string]$InstanceName) {

    $code = {

        param (

            [string] $InstanceName
        )

        Restart-NavServerInstance -ServerInstance $InstanceName -Force -Confirm:$false
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Neustarten der Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function NewWebServerInstance([string]$InstanceName, [int32]$ClientPort, [int32]$ManagementPort, [string]$ClientType = "SubSite", [string]$CertificateThumbprint = $null, [int]$WebSitePort = 0) {

    $syncHash = [hashtable]::Synchronized(@{ 
    
            Result = [object] 
        })

    $code = {

        param (

            [string]$InstanceName,
            [int32]$ClientPort,
            [int32]$ManagementPort,
            [string]$ClientType,
            [string]$CertificateThumbprint,
            [int]$WebSitePort,
            [hashtable]$SyncHash
        )

        $p = @{

            WebServerInstance      = $InstanceName
            Server                 = $env:COMPUTERNAME
            ServerInstance         = $InstanceName
            ClientServicesPort     = $ClientPort
            ManagementServicesPort = $ManagementPort
            SiteDeploymentType     = $ClientType
        }

        if ($ClientType -eq "RootSite") {

            if ($null -ne $WebSitePort -and 0 -ne $WebSitePort) {

                $p["WebSitePort"] = $WebSitePort
            }

            if (-not [String]::IsNullOrWhiteSpace($CertificateThumbprint)) {

                $p["CertificateThumbprint"] = $CertificateThumbprint
            }
        }

        New-NAVWebServerInstance @p
        Set-NAVWebServerInstanceConfiguration -WebServerInstance $InstanceName -KeyName "SessionTimeout" -KeyValue "06:00:00" -SiteDeploymentType $ClientType
        Set-NAVWebServerInstanceConfiguration -WebServerInstance $InstanceName -KeyName "PersonalizationEnabled" -KeyValue "True" -SiteDeploymentType $ClientType

        $SyncHash.Result = Get-NAVWebServerInstance -WebServerInstance $InstanceName
    }

    [hashtable]$params = @{

        InstanceName          = $InstanceName
        ClientPort            = $ClientPort
        ManagementPort        = $ManagementPort
        ClientType            = $ClientType
        CertificateThumbprint = $CertificateThumbprint
        WebSitePort           = $WebSitePort
        SyncHash              = $syncHash 
    }

    $usedPorts = Get-NetTCPConnection | select -Unique -ExpandProperty LocalPort
    if (($ClientType -eq "RootSite") -and ($null -ne $WebSitePort) -and (0 -ne $WebSitePort) -and ($WebSitePort -in $usedPorts)) {

        throw [Exception]::new("Der angegebene Port $($WebSitePort) ist bereits in Verwendung.")
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
        return $syncHash.Result
    }
    catch [Exception] {

        throw [Exception]::new("Fehler bei der Erstellung der Webserver Instanz:`n$($_.Exception.Message)", $_.Exception)
    }
}


<#
Ruft alle installierten Web Clients ab. Kann mit "-WebInstanceName" auf einen einzelnen Web Client geflitert werden.
#>
function GetWebServerInstances([string]$WebInstanceName = $null) {

    $syncHash = [hashtable]::Synchronized(@{
    
            Result = @() 
        })

    $code = {

        param (

            [string]$WebInstanceName,
            [hashtable]$SyncHash
        )

        if (-not [String]::IsNullOrWhiteSpace($WebInstanceName)) {

            [array]$instances = [PSCustomObject](Get-NAVWebServerInstance -WebServerInstance $WebInstanceName | select *)
        }
        else {

            [array]$instances = [PSCustomObject](Get-NAVWebServerInstance | select *)
        }

        foreach ($instance in $instances) {

            if ([String]::IsNullOrWhiteSpace($instance.'Configuration File') -or -not (Test-Path -Path $instance.'Configuration File')) {

                continue
            }

            $instance | Add-Member -MemberType NoteProperty -Name NAVWebSettings -Value (Get-Content -Path $instance.'Configuration File' -Encoding UTF8 -Raw | ConvertFrom-Json | select -ExpandProperty NAVWebSettings)
        }


        $SyncHash.Result = $instances
    }

    $maxVersion = (NavModule\GetNavInstallations).Values | ? { $_.WebClientInstalled -eq $true } | Sort-Object Version -Descending | select -ExpandProperty Version -First 1
    $params = [hashtable]@{ 
    
        WebInstanceName = $WebInstanceName
        SyncHash        = $syncHash
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version $maxVersion

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance

        return $syncHash.Result
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Abrufen der Web Clients`n$($_.Exception.Message)", $_.Exception)
    }
}


function RemoveWebServerInstance([string]$WebServerInstance) {

    $code = {

        param (

            [string]$WebServerInstance
        )

        Remove-NAVWebServerInstance -WebServerInstance $WebServerInstance -ErrorAction Stop
    }

    try {

        $targetNavVersion = NavModule\GetInstanceNavVersion -InstanceName $WebInstanceName
    }
    catch [Exception] { }

    if ($null -eq $targetNavVersion) {

        $targetNavVersion = (NavModule\GetNavInstallations).Values | ? { $_.WebClientInstalled -eq $true } | Sort-Object Version -Descending | select -ExpandProperty Version -First 1
    }

    $params = [hashtable]@{ 
    
        WebServerInstance = $WebServerInstance 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version $targetNavVersion

    try {

        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Entfernen der Web Server Instance $($WebInstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function GetNavServerUser([string]$InstanceName) {
    
    $syncHash = [hashtable]::Synchronized(@{ 
        
            Result = @() 
        })

    $code = {

        param (

            [string] $InstanceName,
            [Hashtable] $SyncHash
        )

        $SyncHash.Result = Get-NAVServerUser -ServerInstance $InstanceName
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        SyncHash     = $syncHash 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {

        NavModule\InvokePSInstance -Instance $psInstance

        return $syncHash.Result
    }
    catch {

        throw [Exception]::new("Fehler beim Abruf der User:`n$($_.Exception.ToString)", $_.Exception)
    }
}


function GetNavServerUserPermissionSet([string]$InstanceName, [string]$WindowsAccount = $null, [string]$WindowsSecurityId = $null) {

    $syncHash = [hashtable]::Synchronized(@{
    
            Result = @()
        })

    $code = {

        param(

            [string] $InstanceName,
            [string] $WindowsAccount = $null,
            [string] $WindowsSecurityId = $null,
            [Hashtable] $SyncHash
        )
        
        try {

            if (-not [String]::IsNullOrWhiteSpace($WindowsAccount)) {

                $SyncHash.Result = Get-NAVServerUserPermissionSet -ServerInstance $InstanceName -WindowsAccount $WindowsAccount
            }
            elseif (-not [String]::IsNullOrWhiteSpace($WindowsSecurityId)) {

                $SyncHash.Result = Get-NAVServerUserPermissionSet -ServerInstance $InstanceName -Sid $WindowsSecurityId
            }
        }
        catch [Exception] {

            $SyncHash.Result = $null
        }
    }

    $params = [hashtable]@{ 
        
        InstanceName      = $InstanceName
        WindowsAccount    = $WindowsAccount
        WindowsSecurityId = $WindowsSecurityId
        SyncHash          = $syncHash 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {

        NavModule\InvokePSInstance -Instance $psInstance

        return $syncHash.Result
    }
    catch {

        throw [Exception]::new("Fehler beim Abruf der User:`n$($_.Exception.ToString)", $_.Exception)
    }
}


function GetNavCompanies([string]$InstanceName) {

    $syncHash = [hashtable]::Synchronized(@{ 
    
            Result = @() 
        }) 

    $code = {

        param (

            [string]$InstanceName,
            [Hashtable]$SyncHash
        )

        $SyncHash.Result = Get-NAVCompany -ServerInstance $InstanceName -ErrorAction Stop
    }

    $params = [hashtable]@{ 
        
        InstanceName = $InstanceName
        SyncHash     = $syncHash 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {

        NavModule\InvokePSInstance -Instance $psInstance

        return $syncHash.Result
    }
    catch {

        throw [Exception]::new("Fehler beim Abruf der Mandanten:`n$($_.Exception.ToString)", $_.Exception)
    }
}


function GetNavAppInfo([string]$InstanceName, [switch]$SymbolsOnly) {

    $syncHash = [hashtable]::Synchronized(@{
    
            Result = @()
        })

    $code = {

        param(

            [string] $InstanceName,
            [boolean] $SymbolsOnly,
            [hashtable] $SyncHash
        )

        $p = @{
            
            ServerInstance = $InstanceName
            SymbolsOnly    = $SymbolsOnly
        }

        $SyncHash.Result = Get-NAVAppInfo @p
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        SymbolsOnly  = $SymbolsOnly.IsPresent
        SyncHash     = $syncHash 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {

        NavModule\InvokePSInstance -Instance $psInstance

        return $syncHash.Result
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Abrufen der App Informationen auf Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function InstallNavApp([string]$InstanceName, [string]$Path = $null, [string]$AppName = $null, [string]$AppVersion = $null) {

    $code = {

        param (

            [string]$InstanceName,
            [string]$Path = $null,
            [string]$AppName = $null,
            [string]$AppVersion = $null
        )

        $p = @{

            ServerInstance = $InstanceName
            Force          = $true
        }

        if (-not [String]::IsNullOrWhiteSpace($Path)) {

            $p["Path"] = $Path
        }
        elseif (-not [String]::IsNullOrWhiteSpace($AppName)) {

            $p["Name"] = $AppName
            if (-not [String]::IsNullOrWhiteSpace($AppVersion)) {

                $p["Version"] = $AppVersion
            }
        }

        Install-NAVApp @p
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        Path         = $Path
        AppName      = $AppName
        AppVersion   = $AppVersion
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Installieren der App $($Path) auf Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function UninstallNavApp([string]$InstanceName, [string]$AppName, [string]$AppVersion) {

    $code = {

        param(

            [string] $InstanceName,
            [string] $AppName,
            [string] $AppVersion
        )

        Uninstall-NAVApp -ServerInstance $InstanceName -Name $AppName -Version $AppVersion -Force -WarningAction SilentlyContinue
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        AppName      = $AppName
        AppVersion   = $AppVersion
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {

        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Deinstallieren der App Informationen auf Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function PublishNavApp([string]$InstanceName, [string]$Path, [switch]$SkipVerification, [string]$PackageType = $null) {

    $code = {

        param (

            [string]$InstanceName,
            [string]$Path,
            [boolean]$SkipVerification,
            [string]$PackageType = $null
        )

        $p = @{

            ServerInstance   = $InstanceName
            Path             = $Path
            SkipVerification = $SkipVerification
        }

        if (-not [String]::IsNullOrWhiteSpace($PackageType)) {

            $p["PackageType"] = $PackageType
        }

        Publish-NavApp @p
    }

    $params = [hashtable]@{ 
        
        InstanceName     = $InstanceName
        Path             = $Path
        SkipVerification = $SkipVerification.IsPresent
        PackageType      = $PackageType 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Publishen der App $($Path) auf Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function UnpublishNavApp([string]$InstanceName, [string]$AppName, [string]$AppVersion) {

    $code = {

        param(

            [string] $InstanceName,
            [string] $AppName,
            [string] $AppVersion
        )

        Unpublish-NAVApp -ServerInstance $InstanceName -Name $AppName -Version $AppVersion
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        AppName      = $AppName
        AppVersion   = $AppVersion
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {

        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Deinstallieren der App Informationen auf Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function SyncNavApp([string]$InstanceName, [string]$AppName, [string]$Mode, [string]$AppVersion = $null) {

    $code = {

        param(

            [string]$InstanceName,
            [string]$AppName,
            [string]$Mode,
            [string]$AppVersion = $null
        )

        $p = @{
            ServerInstance = $InstanceName
            Name           = $AppName
            Mode           = $Mode
            Force          = $true
        }

        if (-not [String]::IsNullOrWhiteSpace($AppVersion)) {

            $p.Add("Version", $AppVersion)
        }

        Sync-NAVApp @p
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        AppName      = $AppName
        AppVersion   = $AppVersion
        Mode         = $Mode 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Syncen der App $($appName) in $($instanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function SyncNavTenant([string]$InstanceName, [string]$TenantName, [string]$Mode) {

    $code = {
        
        param(
            
            [string]$InstanceName,
            [string]$TenantName,
            [string]$Mode
        )

        $p = @{
            Force       = $true
            ErrorAction = "Stop"
            Mode        = $Mode
        }

        if (-not ([String]::IsNullOrWhiteSpace($InstanceName))) {

            $p.Add("ServerInstance", $InstanceName)
        }

        if (-not ([String]::IsNullOrWhiteSpace($TenantName))) {

            $p.Add("Tenant", $TenantName)
        }

        Sync-NAVTenant @p
        Start-Sleep -Seconds 5
        $tenantState = Get-NavTenant -ServerInstance $InstanceName -Tenant default | select -ExpandProperty State
        while ($tenantState -like "*progress*") {
            Start-Sleep -Seconds 10
            $tenantState = Get-NavTenant -ServerInstance $InstanceName -Tenant default | select -ExpandProperty State
        }

        if ($tenantState -notin @("Operational", "OperationalSyncInProgress") -or $tenantState -like "*fail*") {

            throw [Exception]::new("Sync-Navtenant failed with state $($tenantState)")
        }

        <#
        Mounted
        Dismounted
        Failed
        OperationalWithSyncPending
        OperationalWithSyncFailure
        OperationalSyncInProgress
        Operational
        OperationalDataUpgradePending
        OperationalDataUpgradeInProgress
        OperationalWithDataUpgradeFailure
        OperationalWithMissingApplicationVersionFailure
        Mounting
        OperationalTenantDataCopyInProgress
        OperationalTenantDataCopyFailed
        OperationalTenantDataMoveInProgress
        OperationalTenantRemoveInProgress
        OperationalTenantRemoveFailed
        #>
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        TenantName   = $TenantName
        Mode         = $Mode 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Syncen des Mandanten $($TenantName) in $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


<#
Konvertiert die angegebene NAV Datenbank von Business Central 140 auf 170 / 180.
#>
function InvokeNAVApplicationDatabaseConversion([string]$DatabaseServerInstance, [string]$DatabaseName, [pscredential]$DatabaseCredentials = $null, [ValidateSet("170", "180")][string]$TargetVersion) {

    $code = {

        param (

            [string]$DatabaseServerInstance,
            [string]$DatabaseName,
            [pscredential]$DatabaseCredentials = $null

        )

        $p = @{

            DatabaseServer = $DatabaseServerInstance
            DatabaseName   = $DatabaseName
            Force          = $true
            Verbose        = $true
            ErrorAction    = "Stop"
        }

        if ($null -ne $DatabaseServerInstance) {

            $p.Add("ApplicationDatabaseCredentials", $DatabaseCredentials)
        }

        Invoke-NAVApplicationDatabaseConversion @p
    }

    $params = [hashtable]@{ 
    
        DatabaseServerInstance = $DatabaseServerInstance
        DatabaseName           = $DatabaseName
        DatabaseCredentials    = $DatabaseCredentials
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version $TargetVersion

    try {
            
        NavModule\InvokePSInstance -instance $psInstance -Verbose
    }
    catch [Exception] {

        throw [Exception]::new("Fehler bei der Konvertierung der Datenbank $($databaseName) auf $($databaseServerInstance):`n$($_.Exception.Message)", $_.Exception)
    }
}


function InvokeCodeunit([string]$InstanceName, [string]$CodeunitId, [string]$FunctionName, [string]$CompanyName = $null, [string]$Language = $null, [string]$Argument = $null) {

    $code = {

        param(

            [string]$InstanceName,
            [string]$CodeunitId,
            [string]$FunctionName,
            [string]$CompanyName = $null,
            [string]$Language = $null,
            [string]$Argument = $null
        )

        $p = @{

            ServerInstance = $InstanceName
            CodeunitId     = $CodeunitId
            MethodName     = $FunctionName
            Force          = $true
        }

        if (-not [String]::IsNullOrWhiteSpace($CompanyName)) {

            $p["CompanyName"] = $CompanyName
        }
        if (-not [String]::IsNullOrWhiteSpace($Language)) {

            $p["Language"] = $Language
        }
        if (-not [String]::IsNullOrWhiteSpace($Argument)) {

            $p["Argument"] = $Argument
        }

        Invoke-NAVCodeunit @p
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        CodeunitId   = $CodeunitId
        FunctionName = $FunctionName
        CompanyName  = $CompanyName 
        Language     = $Language
        Argument     = $Argument
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim AUsführen der Codeunit $($CodeunitId) in $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}

<#
Importiert die angegebene Lizenz.
LicensePath -> Die Lizenz unter dem angegebenen Pfad wird importiert.
Base64License -> Die Entwicklerlizenz kann als Base64 übergeben werden.
#>
function ImportNavServerLicense {

    param (
        
        [string]$InstanceName,
        
        [string]$LicensePath, 
        
        [Parameter(ParameterSetName = "Base64License")]
        [string]$Base64License,

        [Parameter(ParameterSetName = "Base64License", Mandatory = $true)]
        [string]$WorkingDir
    )

    $navVersion = NavModule\GetInstanceNavVersion -InstanceName $InstanceName

    if ([String]::IsNullOrWhiteSpace($LicensePath) -and -not ([String]::IsNullOrWhiteSpace($Base64License))) {

        $devLicenseTempPath = [System.IO.Path]::Combine($WorkingDir, "$($navVersion)_devlicense.flf")
        $licenseBytes = [System.Convert]::FromBase64String($Base64License)
        [System.IO.File]::WriteAllBytes($devLicenseTempPath, $licenseBytes) | Out-Null

        $LicensePath = $devLicenseTempPath
    }

    $code = {

        param (

            [string]$InstanceName,
            [string]$LicenseFile
        )

        Import-NavServerLicense -ServerInstance $InstanceName -LicenseFile $LicenseFile -Force -ErrorAction Stop
    }

    $params = [hashtable]@{ 
        
        InstanceName = $InstanceName
        LicenseFile  = $LicensePath 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version $navVersion

    try {

        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {
            
        throw [Exception]::new("Fehler beim Importieren der Lizenz in $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
    finally {

        if (-not [String]::IsNullOrWhiteSpace($devLicenseTempPath)) {

            Remove-Item -Path $devLicenseTempPath -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }
}


function InstallMicrosoftJSAddin([string]$InstanceName, [string]$AddinName, [string]$AddinLocation) {
    
    $code = {

        param(

            [string]$InstanceName,
            [string]$AddinName,
            [string]$AddinLocation,
            [string]$ServiceTierDir
        )

        if (Get-NAVAddin  -ServerInstance $InstanceName -AddInName $AddinName -PublicKeyToken 31bf3856ad364e35) {
            
            Set-NAVAddIn -ServerInstance $InstanceName -AddInName $AddinName -PublicKeyToken 31bf3856ad364e35 -ResourceFile ([System.IO.Path]::Combine($ServiceTierDir, "Add-ins", $AddinLocation)) -ErrorAction Stop
        }
        else {
            
            New-NAVAddin -ServerInstance $InstanceName -AddInName $AddinName -PublicKeyToken 31bf3856ad364e35 -ResourceFile ([System.IO.Path]::Combine($ServiceTierDir, "Add-ins", $AddinLocation)) -ErrorAction Stop
        }
    }

    $navVersion = NavModule\GetInstanceNavVersion -InstanceName $InstanceName
    $servicePath = (NavModule\GetNavInstallations)[$navVersion].ServicePath

    $params = [hashtable]@{ 
    
        InstanceName   = $InstanceName
        AddinName      = $AddinName
        AddinLocation  = $AddinLocation
        ServiceTierDir = $ServicePath 
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version $navVersion

    try {
            
        NavModule\InvokePSInstance -instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Installieren des JS AddIns $($AddinName) in $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


<#
Vergleicht zwei Objekte miteinander. Wird für den Schemavergleich im Check verwendet.
#>
function CompareNAVTablesProperties([PSObject]$ReferenceObject, [PSObject]$DifferenceObject, [int]$TableId) {

    # Alle Properties auslesen
    $objprops = $ReferenceObject | Get-Member -MemberType Property, NoteProperty | select -ExpandProperty Name
    $objprops += $DifferenceObject | Get-Member -MemberType Property, NoteProperty | select -ExpandProperty Name
    $objprops = $objprops | Select-Object -Unique | Sort-Object 

    $diffs = @()

    # Über jedes Property iterieren
    foreach ($objprop in $objprops) {

        # Übersetzte Systemtabellen ignorieren
        if (($TableId -eq 5011424) -or ($TableId -ge 2000000000 -and $objProp -in @('TableName', 'OptionString'))) {

            continue
        }

        # Property aus beiden Objekten vergleichen
        $diff = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -Property $objprop
        
        if ($null -ne $diff) {            

            # Abweichung ausgeben
            $diffs += [PSCustomObject]@{

                PropertyName = $objprop
                RefValue     = $ReferenceObject.($objprop)
                DiffValue    = $DifferenceObject.($objprop)
            }
        }        
    }

    return $diffs
}


function GetNavCompaniesWithChangelogEnabled([Parameter(ParameterSetName = "Instance")][string]$InstanceName = $null, [Parameter(ParameterSetName = "Database")][string]$DatabaseServerInstance = $null, [Parameter(ParameterSetName = "Database")][string]$DatabaseName = $null) {

    if ($PSCmdlet.ParameterSetName -eq "Instance") {

        $navInstance = NavModule\GetNavInstances -InstanceName $InstanceName | select -First 1
        $DatabaseServerInstance = $navInstance.DatabaseServerName
        if (-not [String]::IsNullOrWhiteSpace($navInstance.DatabaseServerInstance)) {

            $DatabaseServerInstance += "\" + $navInstance.DatabaseServerInstance
        }
        $DatabaseName = $navInstance.DatabaseName
    }

    $companies = SqlModule\ExecuteQuery -Query "SELECT [Name] FROM dbo.Company" -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName | select -ExpandProperty Name
    

    $companiesWithChangelog = @()

    foreach ($company in $companies) {

        $isChangeLogEnabled = SqlModule\ExecuteQuery -DatabaseServerInstance $DatabaseServerInstance -DatabaseName $DatabaseName -Query "
            
            SELECT
                CASE (SELECT 1 FROM [$($DatabaseName)].[dbo].[$($company.Replace('.', '_'))`$Change Log Setup] WHERE [Change Log Activated] = 1)
                WHEN 1 THEN 1
                ELSE 0
            END AS ChangeLogEnabled    
        " | select -ExpandProperty ChangeLogEnabled

        if ($isChangeLogEnabled) {

            $companiesWithChangelog += $company
        }
    }

    return $companiesWithChangelog
}


function StartNavAppDataUpgrade([string]$InstanceName, [string]$AppName, [Version]$AppVersion) {

    $code = {
        
        param(
            
            [string]$InstanceName,
            [string]$AppName,
            [string]$AppVersion
        )

        Start-NavAppDataUpgrade -ServerInstance $InstanceName -Name $AppName -Version $AppVersion -Force | Out-Null
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
        AppName      = $AppName
        AppVersion   = $AppVersion
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim DataUpgrade der App $($AppName) in $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}

function StartNavDataUpgrade([string]$InstanceName) {

    $code = {
        
        param(
            
            [string]$InstanceName
        )

        Start-NavDataUpgrade -ServerInstance $InstanceName -SkipAppVersionCheck -Force -WarningAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 5
        $tenantState = Get-NavDataUpgrade -ServerInstance $InstanceName -Tenant default | select -ExpandProperty State
        while ($tenantState -eq "InProgress" -or $tenantState -eq "OperationalDataUpgradeInProgress") {
            Start-Sleep -Seconds 10
            $tenantState = Get-NavDataUpgrade -ServerInstance $InstanceName -Tenant default | select -ExpandProperty State
        }

        if ($tenantState -notin @("Completed", "NotStarted")) {

            throw [Exception]::new("Start-NavDataUpgrade failed with state $($tenantState)")
        }
    }

    $params = [hashtable]@{ 
    
        InstanceName = $InstanceName
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {
            
        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim DataUpgrade der App $($AppName) in $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}


function SetNavApplication([string]$InstanceName, [Version]$ApplicationVersion) {

    $code = {

        param(

            [string] $InstanceName,
            [Version]$ApplicationVersion
        )

        $p = @{
            
            ServerInstance     = $InstanceName
            ApplicationVersion = $ApplicationVersion
        }

        Set-NavApplication @p -force
    }

    $params = [hashtable]@{ 
    
        InstanceName       = $InstanceName
        ApplicationVersion = $ApplicationVersion
    }

    $psInstance = NavModule\GetPSInstance -Code $code -ScriptParams $params -Version (NavModule\GetInstanceNavVersion -InstanceName $InstanceName)

    try {

        NavModule\InvokePSInstance -Instance $psInstance
    }
    catch [Exception] {

        throw [Exception]::new("Fehler beim Abrufen der App Informationen auf Instanz $($InstanceName):`n$($_.Exception.Message)", $_.Exception)
    }
}