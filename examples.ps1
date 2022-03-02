Import-Module NavModule

# Convert Database to newer version
InvokeNAVApplicationDatabaseConversion -DatabaseServerInstance "localhost" -DatabaseName "MyApp" -TargetVersion $version | Out-Null

# Create instance
$newInstance = NewNavInstance -InstanceName "MyApp" `
    -DatabaseServerInstance "localhost" `
    -DatabaseName "MyApp" `
    -Version "180" `
    -ServiceUserCredentials ([PSCredential]::new("CONTOSO\Administrator", (ConvertTo-SecureString -AsPlainText -Force -String "Passw0rd"))) `
    -ClientPort 3030 `
    -ManagementPort 3031 `
    -ODataPort 3032 `
    -SOAPPort 3033 `
    -DeveloperPort 3034 `
    -Configuration ([hashtable]@{
        SQLCommandTimeout           = "3.00:00:00"
        SqlConnectionIdleTimeout    = "00:10:00"
        SqlConnectionTimeout        = "00:05:00"
        SqlManagementCommandTimeout = "-1"
    })

# Import License and restart
ImportNavServerLicense -InstanceName $newInstance.InstanceName -UseDeveloperLicense -WorkingDir "c:\temp"

# Restart NAV Instance
RestartNavServerInstance -InstanceName $newInstance.InstanceName | Out-Null

# Sync Tenant
SyncNavTenant -InstanceName $newInstance.InstanceName -Mode "ForceSync"

# Get all instances of all installed NAV Versions
$instances = GetNavInstances

# Get all NAV Users of a specific NAV Instance
$users = GetNavServerUser -InstanceName "MyApp"