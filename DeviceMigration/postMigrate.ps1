<# POSTMIGRATE.PS1
Synopsis
PostMigrate.ps1 is run after the migration reboots have completed and the user signs into the PC.
DESCRIPTION
This script is used to update the device group tag in Entra ID and set the primary user in Intune and migrate the bitlocker recovery key.  The device is then registered with AutoPilot.
USE
.\postMigrate.ps1
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

# Wait for Internet for logging
Wait-ForInternetConnection

# Start Transcript
Start-Transcript -Path "$($config.transcriptsPath)\Transcript-postMigrate.log" -Verbose
Write-Log "Starting PostMigrate.ps1..."

# Initialize script
$localPath = $config.localPath
if (!(Test-Path $localPath)) {
    Write-Log "$($localPath) does not exist.  Creating..."
    mkdir $localPath
}
else {
    Write-Log "$($localPath) already exists."
}

# Check context
$context = whoami
Write-Log "Running as $($context)"

# disable postMigrate task
Write-Log "Disabling postMigrate task..."
Disable-ScheduledTask -TaskName "postMigrate"
Write-Log "postMigrate task disabled."

# enable displayLastUserName
Write-Log "Enabling displayLastUserName..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 0 -Verbose
Write-Log "Enabled displayLastUserName."

# authenticate to target tenant if exists
if ($config.targetTenant.tenantName) {
    Write-Log "Authenticating to target tenant..."
    $headers = msGraphAuthenticate -tenantName $config.targetTenant.tenantName -clientID $config.targetTenant.clientID -clientSecret $config.targetTenant.clientSecret
    Write-Log "Authenticated to target tenant."
}
else {
    Write-Log "No target tenant specified.  Authenticating into source tenant."
    $headers = msGraphAuthenticate -tenantName $config.sourceTenant.tenantName -clientID $config.sourceTenant.clientID -clientSecret $config.sourceTenant.clientSecret
    Write-Log "Authenticated to source tenant."
}

# Get current device Intune and Entra attributes
Write-Log "Getting current device attributes..."
$intuneDeviceId = ((Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Issuer -match "Microsoft Intune MDM Device CA" } | Select-Object Subject).Subject).TrimStart("CN=")
$entraDeviceId = ((Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Issuer -match "MS-Organization-Access" } | Select-Object Subject).Subject).TrimStart("CN=")
$entraId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/devices?`$filter=deviceid eq '$entraDeviceId'" -Headers $headers).value.id

# setPrimaryUser
[string]$targetUserId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "NEW_entraUserID").NEW_entraUserID
[string]$sourceUserId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "OLD_entraUserID").OLD_entraUserID
    
if ([string]::IsNullOrEmpty($targetUserId)) {
    Write-Log "Target user not found- proceeding with source user $($sourceUserId)."
    $userId = $sourceUserId
}
else {
    Write-Log "Target user found- proceeding with target user $($targetUserId)."
    $userId = $targetUserId
}
$userUri = "https://graph.microsoft.com/beta/users/$userId"
$id = "@odata.id"
$JSON = @{ $id = $userUri } | ConvertTo-Json
try {
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneDeviceId/users/`$ref" -Method Post -Headers $headers -Body $JSON -ContentType "application/json"
    Write-Log "Primary user set to $($userId)."
}
catch {
    $message = $_.Exception.Message
    Write-Log "Error setting primary user: $message"
}

# updateGroupTag
$tag1 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "OLD_groupTag").OLD_groupTag
$tag2 = $config.groupTag

if ([string]::IsNullOrEmpty($tag1)) {
    $groupTag = $tag2
}
elseif ([string]::IsNullOrEmpty($tag2)) {
    $groupTag = $tag1
}
else {
    $groupTag = $null
    Write-Log "Group tag not found"
}

if (![string]::IsNullOrEmpty($groupTag)) {
    Write-Log "Updating group tag to $($groupTag)..."
    $entraDeviceObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$entraId" -Headers $headers
    $physicalIds = $entraDeviceObject.physicalIds
    $newTag = "[OrderID]:$groupTag"
    $physicalIds += $newTag

    $body = @{
        physicalIds = $physicalIds
    } | ConvertTo-Json
        
    try {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$entraId" -Method Patch -Headers $headers -Body $body
        Write-Log "Group tag updated to $($groupTag)."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Error updating group tag: $message"
    }
}
else {
    Write-Log "No group tag found."
}




# FUNCTION: migrateBitlockerKey
function migrateBitlockerKey() {
    Param(
        [string]$mountPoint = "C:",
        [PSCustomObject]$bitLockerVolume = (Get-BitLockerVolume -MountPoint $mountPoint),
        [string]$keyProtectorId = ($bitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).KeyProtectorId
    )
    if ($bitLockerVolume.KeyProtector.count -gt 0) {
        BackupToAAD-BitLockerKeyProtector -MountPoint $mountPoint -KeyProtectorId $keyProtectorId
        Write-Log "Bitlocker recovery key migrated."
    }
    else {
        Write-Log "No bitlocker recovery key found."
    }
}

# FUNCTION: decryptDrive
function decryptDrive() {
    Param(
        [string]$mountPoint = "C:"
    )
    Disable-BitLocker -MountPoint $mountPoint
    Write-Log "Drive decrypted."
}

# check bitlocker settings in config file and either migrate or decrypt
Write-Log "Checking bitlocker settings..."
if ($config.bitlocker -eq "MIGRATE") {
    Write-Log "Migrating bitlocker recovery key..."
    try {
        migrateBitlockerKey
        Write-Log "Bitlocker recovery key migrated."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Error migrating bitlocker recovery key: $message"
    }
}
elseif ($config.bitlocker -eq "DECRYPT") {
    Write-Log "Decrypting drive..."
    try {
        decryptDrive
        Write-Log "Drive decrypted."
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Error decrypting drive: $message"
    }
}
else {
    Write-Log "Bitlocker settings not found."
}

# Register device in Autopilot
Write-Log "Registering device in Autopilot..."

# Get hardware info
$serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
$hardwareId = ((Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
if ([string]::IsNullOrEmpty($groupTag)) {
    $tag = ""
}
else {
    $tag = $groupTag
}

# Construct JSON
$json = @"
{
    "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
    "groupTag":"$tag",
    "serialNumber":"$serialNumber",
    "productKey":"",
    "hardwareIdentifier":"$hardwareId",
    "assignedUserPrincipalName":"",
    "state":{
        "@odata.type":"microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
        "deviceImportStatus":"pending",
        "deviceRegistrationId":"",
        "deviceErrorCode":0,
        "deviceErrorName":""
    }
}
"@

# Post device
try {
    Invoke-RestMethod -Method Post -Body $json -ContentType "application/json" -Uri "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities" -Headers $headers
    Write-Log "Device registered in Autopilot."
}
catch {
    $message = $_.Exception.Message
    Write-Log "Error registering device in Autopilot: $message"
}

# reset lock screen caption
# Specify the registry key path
$registryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Specify the names of the registry entries to delete
$entryNames = @("legalnoticecaption", "legalnoticetext")

# Loop through each entry and delete it
foreach ($entryName in $entryNames) {
    try {
        Remove-ItemProperty -Path $registryKeyPath -Name $entryName -Force
        Write-Log "Deleted registry entry: $entryName"
    }
    catch {
        Write-Log "Failed to delete registry entry: $entryName. Error: $_"
    }
}


# Cleanup
Write-Log "Cleaning up migration files..."
Remove-Item -Path $config.localPath -Recurse -Force
Write-Log "Migration files cleaned up."

# Remove scheduled tasks
Write-Log "Removing scheduled tasks..."
$tasks = @("reboot", "postMigrate")
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
    Write-Log "$task task removed."
}

# Remove MigrationUser
Write-Log "Removing MigrationUser..."
Remove-LocalUser -Name "MigrationInProgress" -Force
Write-Log "MigrationUser removed."

# End Transcript
Write-Log "Device migration complete"
Stop-Transcript