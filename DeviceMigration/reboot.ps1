<# REBOOT.PS1
Synopsis
Reboot.ps1 automatically changes the userSid and user profile ownership to the new user and reboots the machine.
DESCRIPTION
This script is used to change ownership of the original user profile to the destination user and then reboot the machine.  It is executed by the 'reboot' scheduled task.
USE
.\reboot.ps1
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
Start-Transcript -Path "$($config.transcriptsPath)\Transcript-reboot.log" -Verbose
Write-Log "Starting Reboot.ps1..."

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

# disable reboot task
Write-Log "Disabling reboot task..."
Disable-ScheduledTask -TaskName "Reboot"
Write-Log "Reboot task disabled"

# disable auto logon
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Verbose
Write-Log "Auto logon enabled."

# set new wallpaper
# Tobias: Not required. Comes through Intune policies
# $wallpaper = (Get-ChildItem -Path $config.localPath -Filter "*.jpg" -Recurse).FullName
# if ($wallpaper) {
#     Write-Log "Setting wallpaper..."
#     Copy-Item -Path $wallpaper -Destination "C:\Windows\Web\Wallpaper" -Force
#     $imgPath = "C:\Windows\Web\Wallpaper\$($wallpaper | Split-Path -Leaf)"
#     [string]$desktopScreenPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"

#     Write-Log "Setting Lock screen wallpaper..."
#     reg.exe add $desktopScreenPath /v "DesktopImagePath" /t REG_SZ /d $imgPath /f | Out-Host
#     reg.exe add $desktopScreenPath /v "DesktopImageStatus" /t REG_DWORD /d 1 /f | Out-Host
# }

# Retrieve variables from registry
Write-Log "Retrieving variables from registry..."
$regKey = "Registry::$($config.regPath)"
$values = Get-ItemProperty -Path $regKey
$values.PSObject.Properties | ForEach-Object {
    $name = $_.Name
    $value = $_.Value
    if (![string]::IsNullOrEmpty($value)) {
        Write-Log "Retrieved $($name): $value"
        New-Variable -Name $name -Value $value -Force
    }
    else {
        Write-Log "Error retrieving $name"
        exitScript -exitCode 1 -functionName "retrieveVariables"
    }
}


# Remove aadBrokerPlugin from profile
$aadBrokerPath = (Get-ChildItem -Path "$($OLD_profilePath)\AppData\Local\Packages" -Recurse | Where-Object { $_.Name -match "Microsoft.AAD.BrokerPlugin_*" }).FullName
if ($aadBrokerPath) {
    Write-Log "Removing aadBrokerPlugin from profile..."
    Remove-Item -Path $aadBrokerPath -Recurse -Force
    Write-Log "aadBrokerPlugin removed"
}
else {
    Write-Log "aadBrokerPlugin not found"
}

# Create new user profile
Write-Log "Creating $($NEW_SAMName) profile..."
Add-Type -TypeDefinition @"
using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
namespace UserProfile {
    public static class Class {
        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int CreateProfile(
            [MarshalAs(UnmanagedType.LPWStr)] String pszUserSid,
            [MarshalAs(UnmanagedType.LPWStr)] String pszUserName,
            [Out][MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszProfilePath,
            uint cchProfilePath
        );
    }
}
"@

$sb = New-Object System.Text.StringBuilder(260)
$pathLen = $sb.Capacity

try {
    $CreateProfileReturn = [UserProfile.Class]::CreateProfile($NEW_SID, $NEW_SAMName, $sb, $pathLen)
}
catch {
    Write-Error $_.Exception.Message
}

switch ($CreateProfileReturn) {
    0 {
        Write-Output "User profile created successfully at path: $($sb.ToString())"
    }
    -2147024713 {
        Write-Output "User profile already exists."
    }
    default {
        throw "An error occurred when creating the user profile: $CreateProfileReturn"
    }
}

# Delete New profile
Write-Log "Deleting new profile..."
$newProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $NEW_SID }
Remove-CimInstance -InputObject $newProfile -Verbose | Out-Null
Write-Log "New profile deleted."

# Change ownership of user profile
Write-Log "Changing ownership of user profile..."
$currentProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $OLD_SID }
$changes = @{
    NewOwnerSID = $NEW_SID
    Flags       = 0
}
$currentProfile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changes
Start-Sleep -Seconds 1

# Cleanup logon cache
function cleanupLogonCache() {
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$oldUPN = $OLD_UPN
    )
    Write-Log "Cleaning up logon cache..."
    $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach ($GUID in $logonCacheGUID) {
        $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
        if (!($subKeys)) {
            Write-Log "No subkeys found for $GUID"
            continue
        }
        else {
            $subKeys = $subKeys.trim('{}')
            foreach ($subKey in $subKeys) {
                if ($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name") {
                    $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if (!($subFolders)) {
                        Write-Log "Error - no sub folders found for $subKey"
                        continue
                    }
                    else {
                        $subFolders = $subFolders.trim('{}')
                        foreach ($subFolder in $subFolders) {
                            $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                            if ($cacheUsername -eq $oldUserName) {
                                Remove-Item -Path "$logonCache\$GUID\$subKey\$subFolder" -Recurse -Force
                                Write-Log "Registry key deleted: $logonCache\$GUID\$subKey\$subFolder"
                                continue                                       
                            }
                        }
                    }
                }
            }
        }
    }
}

# run cleanupLogonCache
Write-Log "Running cleanupLogonCache..."
try {
    cleanupLogonCache
    Write-Log "cleanupLogonCache completed"
}
catch {
    $message = $_.Exception.Message
    Write-Log "Failed to run cleanupLogonCache: $message"
    Write-Log "Exiting script..."
    exitScript -exitCode 1 -functionName "cleanupLogonCache"
}

# cleanup identity store cache
function cleanupIdentityStore() {
    Param(
        [string]$idCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache",
        [string]$oldUserName = $OLD_UPN
    )
    Write-Log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach ($key in $idCacheKeys) {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if (!($subKeys)) {
            Write-Log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else {
            $subKeys = $subKeys.trim('{}')
            foreach ($subKey in $subKeys) {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if (!($subFolders)) {
                    Write-Log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else {
                    $subFolders = $subFolders.trim('{}')
                    foreach ($subFolder in $subFolders) {
                        $idCacheUsername = Get-ItemPropertyValue -Path "$idCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction SilentlyContinue
                        if ($idCacheUsername -eq $oldUserName) {
                            Remove-Item -Path "$idCache\$key\$subKey\$subFolder" -Recurse -Force
                            Write-Log "Registry path deleted: $idCache\$key\$subKey\$subFolder"
                            continue
                        }
                    }
                }
            }
        }
    }
}

# run cleanup identity store cache if not domain joined
if ($OLD_domainJoined -eq "NO") {
    Write-Log "Running cleanupIdentityStore..."
    try {
        cleanupIdentityStore
        Write-Log "cleanupIdentityStore completed"
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to run cleanupIdentityStore: $message"
        Write-Log "Exiting script..."
        exitScript -exitCode 1 -functionName "cleanupIdentityStore"
    }
}
else {
    Write-Log "Machine is domain joined - skipping cleanupIdentityStore."
}

# update samname in identityStore LogonCache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameLogonCache() {
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$targetSAMName = $OLD_SAMName
    )

    if ($NEW_SAMName -like "$($OLD_SAMName)_*") {
        Write-Log "New user is $NEW_SAMName, which is the same as $OLD_SAMName with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

        $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach ($GUID in $logonCacheGUID) {
            $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
            if (!($subKeys)) {
                Write-Log "No subkeys found for $GUID"
                continue
            }
            else {
                $subKeys = $subKeys.trim('{}')
                foreach ($subKey in $subKeys) {
                    if ($subKey -eq "Name2Sid") {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if (!($subFolders)) {
                            Write-Log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else {
                            $subFolders = $subFolders.trim('{}')
                            foreach ($subFolder in $subFolders) {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if ($detectedUserSID -eq $NEW_SID) {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    Write-Log "Attempted to update SAMName value (in Name2Sid registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else {
                                    Write-Log "Detected Sid '$detectedUserSID' is for different user - skipping Sid in Name2Sid registry folder..."
                                }
                            }
                        }
                    }
                    elseif ($subKey -eq "SAM_Name") {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if (!($subFolders)) {
                            Write-Log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else {
                            $subFolders = $subFolders.trim('{}')
                            foreach ($subFolder in $subFolders) {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if ($detectedUserSID -eq $NEW_SID) {
                                    Rename-Item "$logonCache\$GUID\$subKey\$subFolder" -NewName $targetSAMName -Force
                                    Write-Log "Attempted to update SAM_Name key name (in SAM_Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else {
                                    Write-Log "Skipping different user in SAM_Name registry folder (User: $subFolder, SID: $detectedUserSID)..."
                                }
                            }
                        }
                    }
                    elseif ($subKey -eq "Sid2Name") {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if (!($subFolders)) {
                            Write-Log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else {
                            $subFolders = $subFolders.trim('{}')
                            foreach ($subFolder in $subFolders) {
                                if ($subFolder -eq $NEW_SID) {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    Write-Log "Attempted to update SAM_Name value (in Sid2Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else {
                                    Write-Log "Skipping different user SID ($subFolder) in Sid2Name registry folder..."
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        Write-Log "New username is $NEW_SAMName, which does not match older username ($OLD_SAMName) with _##### appended to end. SamName LogonCache registry will not be updated."
    }
}

# run updateSamNameLogonCache
Write-Log "Running updateSamNameLogonCache..."
try {
    updateSamNameLogonCache
    Write-Log "updateSamNameLogonCache completed"
}
catch {
    $message = $_.Exception.Message
    Write-Log "Failed to run updateSamNameLogonCache: $message"
    Write-Log "Exiting script..."
    exitScript -exitCode 1 -functionName "updateSamNameLogonCache"
}

# update samname in identityStore Cache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameIdentityStore() {
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$targetSAMName = $OLD_SAMName
    )
    if ($NEW_SAMName -like "$($OLD_SAMName)_*") {
        Write-Log "Cleaning up identity store cache..."
        $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach ($key in $idCacheKeys) {
            $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
            if (!($subKeys)) {
                Write-Log "No keys listed under '$idCache\$key' - skipping..."
                continue
            }
            else {
                $subKeys = $subKeys.trim('{}')
                foreach ($subKey in $subKeys) {
                    $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if (!($subFolders)) {
                        Write-Log "No subfolders detected for $subkey- skipping..."
                        continue
                    }
                    else {
                        $subFolders = $subFolders.trim('{}')
                        foreach ($subFolder in $subFolders) {
                            if ($subFolder -eq $NEW_SID) {
                                Set-ItemProperty -Path "$idCache\$key\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                Write-Log "Attempted to update SAMName value to $targetSAMName."
                            }
                            else {
                                Write-Log "Skipping different user SID ($subFolder) in $subKey registry folder..."
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        Write-Log "New username is $NEW_SAMName, which does not match older username ($OLD_SAMName) with _##### appended to end. SamName IdentityStore registry will not be updated."
    }
}

# run updateSamNameIdentityStore if not domain joined
if ($OLD_domainJoined -eq "NO") {
    Write-Log "Running updateSamNameIdentityStore..."
    try {
        updateSamNameIdentityStore
        Write-Log "updateSamNameIdentityStore completed"
    }
    catch {
        $message = $_.Exception.Message
        Write-Log "Failed to run updateSamNameIdentityStore: $message"
        Write-Log "Exiting script..."
        exitScript -exitCode 1 -functionName "updateSamNameIdentityStore"
    }
}
else {
    Write-Log "Machine is domain joined - skipping updateSamNameIdentityStore."
}

# enable logon provider
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /v "Disabled" /t REG_DWORD /d 0 /f | Out-Host
Write-Log "Enabled logon provider."

# set lock screen caption
if ($config.targetTenant.tenantName) {
    $tenant = $config.targetTenant.tenantName
}
else {
    $tenant = $config.sourceTenant.tenantName
}
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticecaption" /t REG_SZ /d "Welcome to $($tenant)" /f | Out-Host 
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticetext" /t REG_SZ /d "Please Log in with your new email address" /f | Out-Host
Write-Log "Lock screen caption set."


Write-Log "Reboot.ps1 complete"
shutdown -r -t 00
Stop-Transcript

