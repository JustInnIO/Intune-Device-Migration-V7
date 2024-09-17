<# INTUNE TENANT-TO-TENANT DEVICE MIGRATION V7.0
Synopsis
This solution will automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be Hybrid Entra Joined, Active Directory Domain Joined, or Entra Joined.
DESCRIPTION
Intune Device Migration Solution leverages the Microsoft Graph API to automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.  The solution will also migrate the device's primary user profile data and files.  The solution leverages Windows Configuration Designer to create a provisioning package containing a Bulk Primary Refresh Token (BPRT).  Tasks are set to run after the user signs into the PC with destination tenant credentials to update Intune attributes including primary user, Entra ID device group tag, and device category.  In the last step, the device is registered to the destination tenant Autopilot service.  
USE
This script is packaged along with the other files into an intunewin file.  The intunewin file is then uploaded to Intune and assigned to a group of devices.  The script is then run on the device to start the migration process.

NOTES
When deploying with Microsoft Intune, the install command must be "%WinDir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File startMigrate.ps1" to ensure the script runs in 64-bit mode.
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt
Jesse Weimer
#>

$ErrorActionPreference = "SilentlyContinue"

# Import functions
. "$((Get-location).path)\functions.ps1"


# Initialize script
Initialize-Script

# Start Transcript
Start-Transcript -Path "$($config.localPath)\startMigrate.log" -Verbose
Write-Log "Starting Device Migration V-7..."

# Initialize script
$localPath = $config.localPath
if (!(Test-Path $localPath)) {
    Write-Log"$($localPath) does not exist.  Creating..."
    mkdir $localPath
}
else {
    Write-Log "$($localPath) already exists."
}

# Set Intune install tag
New-Item -ItemType File -Path "$($localPath)\install.tag" -Force -Verbose

# Check context
$context = whoami
Write-Log "Running as $($context)"

# Copy package files to local machine
$destination = $config.localPath
Write-Log "Copying package files to $($destination)..."
Copy-Item -Path ".\*" -Destination $destination -Recurse -Force
Write-Log "Package files copied successfully."

# Authenticate to source tenant if exists
Write-Log "Checking for source tenant in JSON settings..."
if ([string]::IsNullOrEmpty($config.sourceTenant.tenantName)) {
    Write-Log "Source tenant not found in JSON settings."
    exitScript -exitCode 4 -functionName "sourceTenant"
}
else {
    Write-Log "Source tenant found in JSON settings."
    try {
        Write-Log "Authenticating to source tenant..."
        $GraphHeaders = msGraphAuthenticate -tenantName $config.sourceTenant.tenantname -clientId $config.sourceTenant.clientId -clientSecret $config.sourceTenant.clientSecret
        Write-Log "Authenticated to $($config.sourceTenant.tenantName) source tenant successfully."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to authenticate to $($config.sourceTenant.tenantName) source tenant. Error: $message"
        Write-Log "Exiting script."
        exitScript -exitCode 4 -functionName "msGraphAuthenticate"
    }
}


# Authenticate to target tenant if exists
Write-Log "Checking for target tenant in JSON settings..."
if ([string]::IsNullOrEmpty($config.targetTenant.tenantName)) {
    Write-Log "Target tenant not found in JSON settings."
}
else {
    Write-Log "Target tenant found in JSON settings."
    try {
        Write-Log "Authenticating to target tenant..."
        $targetHeaders = msGraphAuthenticate -tenantName $config.targetTenant.tenantname -clientId $config.targetTenant.clientId -clientSecret $config.targetTenant.clientSecret
        Write-Log "Authenticated to $($config.targetTenant.tenantName) target tenant successfully."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to authenticate to $($config.targetTenant.tenantName) target tenant. Error: $message"
        Write-Log "Exiting script."
        exitScript -exitCode 4 -functionName "msGraphAuthenticate"
    }
}

# Check Microsoft account connection registry policy
Write-Log "Checking Microsoft account connection registry policy..."
$accountConnectionPath = "HKEY_LOCAL_MACHINE:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts"
$accountConnectionName = "AllowMicrosoftAccountConnection"
$accountConnectionValue = Get-ItemProperty -Path $accountConnectionPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $accountConnectionName

# TODO
if (!($accountConnectionValue)) {
    New-ItemProperty -Path $accountConnectionPath -Name $accountConnectionName -Value 1 -Force
    Write-Log "Microsoft account connection registry value was not present - added 'AllowMicrosoftAccountConnection' with DWORD = 1."
}
elseif ($accountConnectionValue -ne 1) {
    Write-Log "Microsoft account connection registry value currently set to $($accountConnectionValue). Changing to 1..."
    Set-ItemProperty -Path $accountConnectionPath -Name $accountConnectionName -Value 1
    Write-Log "Microsoft account connection value updated to 1."
}
else {
    Write-Log "Microsoft account connection registry value is already set to 1."
}

# FUNCTION: deviceObject
# DESCRIPTION: Creates a device object and writes values to registry.
# PARAMETERS: $hostname - The hostname of the device, $serialNumber - The serial number of the device, $azureAdJoined - Whether the device is Azure AD joined, $domainJoined - Whether the device is domain joined, $certPath - The path to the certificate store, $intuneIssuer - The Intune certificate issuer, $azureIssuer - The Azure certificate issuer, $groupTag - The group tag, $mdm - Whether the device is MDM enrolled.

[object]$headers = $GraphHeaders
[string]$hostname = $env:COMPUTERNAME
[string]$serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
[string]$azureAdJoined = (dsregcmd.exe /status | Select-String "AzureAdJoined").ToString().Split(":")[1].Trim()
[string]$domainjoined = (dsregcmd.exe /status | Select-String "DomainJoined").ToString().Split(":")[1].Trim()
[string]$certPath = "Cert:\LocalMachine\My"
[string]$intuneIssuer = "Microsoft Intune MDM Device CA"
[string]$azureIssuer = "MS-Organization-Access"
[string]$groupTag = $config.groupTag
[string]$regPath = $config.regPath
[bool]$mdm = $false
# Get Intune device certificate
$cert = Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -match $intuneIssuer }
# Get Intune and Entra device IDs if certificate exists
if ($cert) {
    $mdm = $true
    $intuneId = ((Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -match $intuneIssuer } | Select-Object Subject).Subject).TrimStart("CN=")
    $entraDeviceId = ((Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -match $azureIssuer } | Select-Object Subject).Subject).TrimStart("CN=")
    # Get Autopilot object if headers provided
    if ($headers) {
        Write-Log "Headers provided.  Checking for Autopilot object..."
        $autopilotObject = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers)
        if (($autopilotObject.'@odata.count') -eq 1) {
            $autopilotId = $autopilotObject.value.id
            if ([string]::IsNullOrEmpty($groupTag)) {
                $groupTag = $autopilotObject.value.groupTag
                Write-Log "Group tag found: $($groupTag)."
            }
            else {
                $groupTag = $null
                Write-Log "Group tag not found."
            }
        }
    }
    else {
        Write-Log "Headers not provided.  Skipping Autopilot object check."            
        $autopilotObject = $null
    }
}
else {
    $intuneId = $null
    $entraDeviceId = $null
    $autopilotId = $null
    $groupTag = $null
}

if ($domainjoined -eq "YES") {
    $localDomain = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Domain"
}
else {
    $localDomain = $null
}
$pc = @{
    hostname      = $hostname
    serialNumber  = $serialNumber
    azureAdJoined = $azureAdJoined
    domainJoined  = $domainJoined
    intuneId      = $intuneId
    entraDeviceId = $entraDeviceId
    autopilotId   = $autopilotId
    groupTag      = $groupTag
    mdm           = $mdm
    localDomain   = $localDomain
}
# Write device object to registry
Write-Log "Writing device object to registry..."
foreach ($x in $pc.Keys) {
    $pcName = "OLD_$($x)"
    $pcValue = $($pc[$x])
    # Check if value is null or empty
    if (![string]::IsNullOrEmpty($pcValue)) {
        Write-Log "Writing $($pcName) with value $($pcValue)..."
        try {
            reg.exe add $regPath /v $pcName /t REG_SZ /d $pcValue /f | Out-Null
            Write-Log "Successfully wrote $($pcName) with value $($pcValue)."
        }
        catch {
            $message = $_.Exception.Message
            Write-Log "Failed to write $($pcName) with value $($pcValue).  Error: $($message)."
        }
    }
    else {
        Write-Log "Value for $($pcName) is null.  Not writing to registry."
    }
}

# get current user info
[object]$headers = $GraphHeaders
[string]$domainJoined = $pc.domainJoined
[string]$azureAdJoined = $pc.azureAdJoined
[string]$regPath = $config.regPath
[string]$userName = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName
[string]$SID = (New-Object System.Security.Principal.NTAccount($userName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
[string]$profilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID)" -Name "ProfileImagePath")
[string]$SAMName = ($userName).Split("\")[1]
    
# If PC is NOT domain joined, get UPN from cache
Write-Log "Attempting to get current user's UPN..."
if ($domainJoined -eq "NO") {
    # If PC is Azure AD joined, get user ID from Graph
    if ($azureAdJoined -eq "YES") {
        $upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($SID)\IdentityCache\$($SID)" -Name "UserName")
        Write-Log "System is Entra ID Joined - detected IdentityCache UPN value: $upn. Querying graph..."
        $entraUserId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers).id
        if ($entraUserId) {
            Write-Log "Successfully obtained Entra User ID: $entraUserId."
        }
        else {
            Write-Log "Could not obtain Entra User ID from UPN value: $upn."
        }
    }
    else {
        Write-Log "System is not domain or Entra joined - setting UPN and Entra User ID values to Null."
        $upn = $null
        $entraUserId = $null
    }
}
else {
    Write-Log "System is domain joined - setting UPN and Entra User ID values to Null."
    $upn = $null
    $entraUserId = $null
}

$currentUser = @{
    userName    = $userName
    upn         = $upn
    entraUserId = $entraUserId
    profilePath = $profilePath
    SAMName     = $SAMName
    SID         = $SID
}
# Write user object to registry
foreach ($x in $currentUser.Keys) {
    $currentUserName = "OLD_$($x)"
    $currentUserValue = $($currentUser[$x])
    # Check if value is null or empty
    if (![string]::IsNullOrEmpty($currentUserValue)) {
        Write-Log "Writing $($currentUserName) with value $($currentUserValue)..."
        try {
            reg.exe add $regPath /v $currentUserName /t REG_SZ /d $currentUserValue /f | Out-Null
            Write-Log "Successfully wrote $($currentUserName) with value $($currentUserValue)."
        }
        catch {
            $message = $_.Exception.Message
            Write-Log "Failed to write $($currentUserName) with value $($currentUserValue).  Error: $($message)."
        }
    }
}

# If target tenant headers exist, get new user object
$newHeaders = ""
if ($targetHeaders) {
    $tenant = $config.targetTenant.tenantName
    Write-Log "Target tenant headers found.  Getting new user object from $tenant tenant..."
    $newHeaders = $targetHeaders
}
else {
    $tenant = $config.sourceTenant.tenantName
    Write-Log "Target tenant headers not found.  Getting new user object from $tenant tenant..."
    $newHeaders = $GraphHeaders
}
$fullUPN = $($currentUser.upn)
$split = $fullUPN -split "(@)", 2
$split[0] += $split[1].Substring(0, 1)
$split[1] += $split[1].Substring(1)
$userLookup = $split[0]
Write-Log "Looking up user where UPN starts with: $userLookup..."
$newUserObject = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=startsWith(userPrincipalName,'$userLookup')" -Headers $newHeaders
# if new user graph request is successful, set new user object
if ($null -ne $newUserObject.value) {
    Write-Log "New user found in $tenant tenant."
    $newUser = @{
        upn         = $newUserObject.value.userPrincipalName
        entraUserId = $newUserObject.value.id
        SAMName     = $newUserObject.value.userPrincipalName.Split("@")[0]
        SID         = $newUserObject.value.securityIdentifier
    }
    # Write new user object to registry
    foreach ($x in $newUser.Keys) {
        $newUserName = "NEW_$($x)"
        $newUserValue = $($newUser[$x])
        if (![string]::IsNullOrEmpty($newUserValue)) {
            Write-Log "Writing $($newUserName) with value $($newUserValue)..."
            try {
                reg.exe add $config.regPath /v $newUserName /t REG_SZ /d $newUserValue /f | Out-Null
                Write-Log "Successfully wrote $($newUserName) with value $($newUserValue)."
            }
            catch {
                $message = $_.Exception.Message
                Write-Log "Failed to write $($newUserName) with value $($newUserValue).  Error: $($message)."
            }
        }
    }
}
else {
    Write-Log "New user not found in $($config.targetTenant.tenantName) tenant.  Prompting user to sign in..."
    
    $installedNuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
    if (-not($installedNuget)) {
        Write-Log "NuGet package provider not installed.  Installing..."
        Install-PackageProvider -Name NuGet -Force
        Write-Log "NuGet package provider installed successfully."
    }
    else {
        Write-Log "NuGet package provider already installed."
    }
    # Check for Az.Accounts module
    $installedAzAccounts = Get-InstalledModule -Name Az.Accounts -ErrorAction SilentlyContinue
    if (-not($installedAzAccounts)) {
        Write-Log "Az.Accounts module not installed.  Installing..."
        Install-Module -Name Az.Accounts -Force
        Write-Log "Az.Accounts module installed successfully."
    }
    else {
        Write-Log "Az.Accounts module already installed."
    }
    $newUserPath = "C:\Users\Public\Documents\newUserInfo.json"
    $timeout = 300
    $checkInterval = 5
    $elapsedTime = 0
    schtasks.exe /create /tn "userFinder" /xml "C:\ProgramData\IntuneMigration\userFinder.xml" /f | Out-Host
    while ($elapsedTime -lt $timeout) {
        if (Test-Path $newUserPath) {
            Write-Log "New user found.  Continuing with script..."
            break
        }
        else {
            Write-Log "New user info not present.  Waiting for user to sign in..."
            Start-Sleep -Seconds $checkInterval
            $elapsedTime += $checkInterval
        }
    }
    if (Test-Path $newUserPath) {
        $newUserInfo = Get-Content -Path "C:\Users\Public\Documents\newUserInfo.json" | ConvertFrom-JSON

        $newUser = @{
            entraUserID = $newUserInfo.entraUserId
            SID         = $newUserInfo.SID
            SAMName     = $newUserInfo.SAMName
            UPN         = $newUserInfo.upn
        }
        foreach ($x in $newUser.Keys) {
            $newUserName = "NEW_$($x)"
            $newUserValue = $($newUser[$x])
            if (![string]::IsNullOrEmpty($newUserValue)) {
                Write-Log "Writing $($newUserName) with value $($newUserValue)..."
                try {
                    reg.exe add "HKLM\SOFTWARE\IntuneMigration" /v $newUserName /t REG_SZ /d $newUserValue /f | Out-Null
                    Write-Log "Successfully wrote $($newUserName) with value $($newUserValue)."
                }
                catch {
                    $message = $_.Exception.Message
                    Write-Log "Failed to write $($newUserName) with value $($newUserValue).  Error: $($message)."
                }
            }
        }
        Write-Host "User found. Continuing with script..."
        Disable-ScheduledTask -TaskName "userFinder"
        Remove-Item -Path $newUserPath -Force -Recurse
    }
    else {
        Write-Log "New user not found.  Exiting script."
        exitScript -exitCode 4 -functionName "newUser"
    }
}       

# Remove MDM certificate if present
if ($pc.mdm -eq $true) {
    Write-Log "Removing MDM certificate..."
    Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Issuer -match "Microsoft Intune MDM Device CA" } | Remove-Item -Force
    Write-Log "MDM certificate removed successfully."
}
else {
    Write-Log "MDM certificate not present."
}

# Remove MDM enrollment
if ($pc.mdm -eq $true) {
    Write-Log "Removing MDM enrollment..."
    $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    $enrollments = Get-ChildItem -Path $enrollmentPath
    foreach ($enrollment in $enrollments) {
        $object = Get-ItemProperty Registry::$enrollment
        $enrollPath = $enrollmentPath + $object.PSChildName
        $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
        if ($key) {
            Write-Log "Removing MDM enrollment $($enrollPath)..."
            Remove-Item -Path $enrollPath -Recure
            Write-Log "MDM enrollment removed successfully."
        }
        else {
            Write-Log "MDM enrollment not present."
        }
    }
    $enrollId = $enrollPath.Split("\")[-1]
    $additionalPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provinsioning\OMADM\Accounts\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$($enrollID)"
    )
    foreach ($path in $additionalPaths) {
        if (Test-Path $path) {
            Write-Log "Removing $($path)..."
            Remove-Item -Path $path -Recurse
            Write-Log "$($path) removed successfully."
        }
        else {
            Write-Log "$($path) not present."
        }
    }
}
else {
    Write-Log "MDM enrollment not present."
}


# Set migration tasks
$tasks = @("reboot", "postMigrate")
foreach ($task in $tasks) {
    $taskPath = "$($config.localPath)\$($task).xml"
    if ([string]::IsNullOrEmpty($taskPath)) {
        Write-Log "$($task) task not found."
    }
    else {
        Write-Log "Setting $($task) task..."
        try {
            schtasks.exe /create /xml $taskPath /tn $task /f | Out-Host
            Write-Log "$($task) task set successfully."
        }
        catch {
            $message = $_.Exception.Message
            Write-Log "Failed to set $($task) task. Error: $message"
            Write-Log "Exiting script."
            exitScript -exitCode 4 -functionName "schtasks"
        }
    }
}


# Leave Azure AD / Entra Join
if ($pc.azureAdJoined -eq "YES") {
    Write-Log "PC is Azure AD Joined.  Leaving Azure AD..."
    try {
        Start-Process -FilePath "C:\Windows\System32\dsregcmd.exe" -ArgumentList "/leave"
        Write-Log "PC left Azure AD successfully."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to leave Azure AD. Error: $message"
        Write-Log "Exiting script."
        exitScript -exitCode 4 -functionName "dsregcmd"
    }
}
else {
    Write-Log "PC is not Azure AD Joined."
}


# Leave Domain/Hybrid Join
$migrateAdmin = "MigrationInProgress"
$adminPW = generatePassword
$adminGroup = Get-CimInstance -Query "Select * From Win32_Group Where LocalAccount = True And SID = 'S-1-5-32-544'"
$adminGroupName = $adminGroup.Name
New-LocalUser -Name $migrateAdmin -Password $adminPW -PasswordNeverExpires
Add-LocalGroupMember -Group $adminGroupName -Member $migrateAdmin

if ($pc.domainJoined -eq "YES") {
    [string]$hostname = $pc.hostname,
    [string]$localDomain = $pc.localDomain

    # Check for line of sight to domain controller
    $pingCount = 4
    $pingResult = Test-Connection -ComputerName $localDomain -Count $pingCount
    if ($pingResult.StatusCode -eq 0) {
        Write-Log "$($hostname) has line of sight to domain controller.  Attempting to break..."
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty InterfaceAlias
        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses ("8.8.8.8", "8.8.4.4")
        Write-Log "Successfully broke line of sight to domain controller."
    }
    else {
        Write-Log "$($hostname) has no line of sight to domain controller."
    }
    Write-Log "Checking $migrateAdmin status..."
    [bool]$acctStatus = (Get-LocalUser -Name $migrateAdmin).Enabled
    if ($acctStatus -eq $false) {
        Write-Log "$migrateAdmin is disabled; setting password and enabling..."
        Get-LocalUser -Name $migrateAdmin | Enable-LocalUser
        Write-Log "Successfully enabled $migrateAdmin."
    }
    else {
        Write-Log "$migrateAdmin is already enabled."
    }
    try {
        $instance = Get-CimInstance -ClassName 'Win32_ComputerSystem'
        $invCimParams = @{
            MethodName = 'UnjoinDomainOrWorkGroup'
            Arguments  = @{ FUnjoinOptions = 0; Username = "$hostname\$migrateAdmin"; Password = "$adminPW" }
        }
        $instance | Invoke-CimMethod @invCimParams
        Write-Log "Successfully unjoined $hostname from domain."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to unjoin $hostname from domain. Error: $message"
        Write-Log "Exiting script."
        exitScript -exitCode 4 -functionName "Remove-Computer"
    }
}
else {
    Write-Log "PC is not domain joined."
}




################### SCCM SECTION ###################
# FUNCTION: removeSCCM
# DESCRIPTION: Removes the SCCM client from the device.
function removeSCCM() {
    [CmdletBinding()]
    Param(
        [string]$CCMpath = "C:\Windows\ccmsetup\ccmsetup.exe",
        [array]$services = @("CcmExec", "smstsmgr", "CmRcService", "ccmsetup"),
        [string]$CCMProcess = "ccmsetup",
        [string]$servicesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\",
        [string]$ccmRegPath = "HKLM:\SOFTWARE\Microsoft\CCM",
        [array]$sccmKeys = @("CCM", "SMS", "CCMSetup"),
        [string]$CSPPath = "HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP",
        [array]$sccmFolders = @("C:\Windows\ccm", "C:\Windows\ccmsetup", "C:\Windows\ccmcache", "C:\Windows\ccmcache2", "C:\Windows\SMSCFG.ini",
            "C:\Windows\SMS*.mif"),
        [array]$sccmNamespaces = @("ccm", "sms")
    )
    
    # Remove SCCM client
    Write-Log "Removing SCCM client..."
    if (Test-Path $CCMpath) {
        Write-Log "Uninstalling SCCM client..."
        Start-Process -FilePath $CCMpath -ArgumentList "/uninstall" -Wait
        if ($CCMProcess) {
            Write-Log "SCCM client still running; killing..."
            Stop-Process -Name $CCMProcess -Force -ErrorAction SilentlyContinue
            Write-Log "Killed SCCM client."
        }
        else {
            Write-Log "SCCM client uninstalled successfully."
        }
        # Stop SCCM services
        foreach ($service in $services) {
            $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($serviceStatus) {
                Write-Log "Stopping $service..."
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped $service."
            }
            else {
                Write-Log "$service not found."
            }
        }
        # Remove WMI Namespaces
        foreach ($namespace in $sccmNamespaces) {
            Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name = '$namespace'" -Namespace "root" | Remove-WmiObject
        }
        # Remove SCCM registry keys
        foreach ($service in $services) {
            $serviceKey = $servicesRegPath + $service
            if (Test-Path $serviceKey) {
                Write-Log "Removing $serviceKey registry key..."
                Remove-Item -Path $serviceKey -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed $serviceKey registry key."
            }
            else {
                Write-Log "$serviceKey registry key not found."
            }
        }
        foreach ($key in $sccmKeys) {
            $keyPath = $ccmRegPath + "\" + $key
            if (Test-Path $keyPath) {
                Write-Log "Removing $keyPath registry key..."
                Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed $keyPath registry key."
            }
            else {
                Write-Log "$keyPath registry key not found."
            }
        }
        # Remove CSP
        Remove-Item -Path $CSPPath -Recurse -Force -ErrorAction SilentlyContinue
        # Remove SCCM folders
        foreach ($folder in $sccmFolders) {
            if (Test-Path $folder) {
                Write-Log "Removing $folder..."
                Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed $folder."
            }
            else {
                Write-Log "$folder not found."
            }
        }
    }
    else {
        Write-Log "SCCM client not found."
    }
}


# Remove SCCM client if required
Write-Log "Checking for SCCM client..."
if ($config.SCCM -eq $true) {
    Write-Log "SCCM enabled.  Removing SCCM client..."
    try {
        removeSCCM
        Write-Log "SCCM client removed successfully."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to remove SCCM client. Error: $message"
        Write-Log "Exiting script."
        exitScript -exitCode 4 -functionName "removeSCCM"
    }
}
else {
    Write-Log "SCCM not enabled."
}

# Install provisioning package
$ppkg = (Get-ChildItem -Path $config.localPath -Filter "*.ppkg" -Recurse).FullName
if ($ppkg) {
    Write-Log "Provisioning package found. Installing..."
    try {
        Install-ProvisioningPackage -PackagePath $ppkg -QuietInstall -Force
        Write-Log "Provisioning package installed."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to install provisioning package. Error: $message"
        Write-Log "Exiting script."
        exitScript -exitCode 4 -functionName "Install-ProvisioningPackage"
    }
}
else {
    Write-Log "Provisioning package not found."
    exitScript -exitCode 4 -functionName "Install-ProvisioningPackage"
}

# Delete Intune and Autopilot object if exist
if ($pc.mdm -eq $true) {
    if ([string]::IsNullOrEmpty($pc.intuneId)) {
        Write-Log "Intune object not found."
    }
    else {
        Write-Log "Deleting Intune object..."
        try {
            Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($pc.intuneId)" -Headers $GraphHeaders
            Start-Sleep -Seconds 2
            Write-Log "Intune object deleted successfully."
        }
        catch {
            $message = $_.Exception.Message
            Write-Log "Failed to delete Intune object. Error: $message"
            Write-Log "Exiting script."
            exitScript -exitCode 4 -functionName "Intune object delete"
        }
    }
    if ([string]::IsNullOrEmpty($pc.autopilotId)) {
        Write-Log "Autopilot object not found."
    }
    else {
        Write-Log "Deleting Autopilot object..."
        try {
            Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($pc.autopilotId)" -Headers $GraphHeaders
            Start-Sleep -Seconds 2
            Write-Log "Autopilot object deleted successfully."
        }
        catch {
            $message = $_.Exception.Message
            Write-Log "Failed to delete Autopilot object. Error: $message"
            Write-Log "Exiting script."
            exitScript -exitCode 4 -functionName "Autopilot object delete"
        }
    }
}
else {
    Write-Log "PC is not MDM enrolled."
}

# FUNCTION: setAutoLogonAdmin
# DESCRIPTION: Sets the auto logon account for the administrator 
# PARAMETERS: $username - The username to set auto logon for, $password - The password to set auto logon for.
[string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Write-Log "Creating local admin account..."
Write-Log "Successfully created local admin account."
reg.exe add $autoLogonPath /v "AutoAdminLogon" /t REG_SZ /d 0 /f | Out-Host
reg.exe add $autoLogonPath /v "DefaultUserName" /t REG_SZ /d $migrateAdmin /f | Out-Host
reg.exe add $autoLogonPath /v "DefaultPassword" /t REG_SZ /d "@Password*123" | Out-Host
Write-Log "Successfully set auto logon to $migrateAdmin."

# Enable auto logon
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1 -Verbose
Write-Log "Auto logon enabled."

# Disable password logon provider
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /v "Disabled" /t REG_DWORD /d 1 /f | Out-Host
Write-Log "Password logon provider disabled."

# Disable DisplayLastUser
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Verbose
Write-Log "DisplayLastUser disabled."

# Set lock screen caption
if ($targetHeaders) {
    $tenant = $config.targetTenant.tenantName
}
else {
    $tenant = $config.sourceTenant.tenantName
}
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticecaption" /t REG_SZ /d "Device Migration in Progress..." /f | Out-Host 
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticetext" /t REG_SZ /d "Your PC is being migrated to the $($tenant) tenant and will automatically reboot in 30 seconds.  Please do not power off." /f | Out-Host
Write-Log "Lock screen caption set successfully."

# Stop transcript and restart
Write-Log "$($pc.hostname) will reboot in 30 seconds..."
Stop-Transcript
shutdown -r -t 30