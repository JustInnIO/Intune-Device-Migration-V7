

# function to initialize the global variables
function Initialize-Script {
        [CmdletBinding()]
        Param(
        )
        # Initialize global variables
        $global:config = Get-Content ".\config.json" | ConvertFrom-Json

        # Get Graph Headers
        $global:MonitorHeaders = msMonitorAuthenticate -tenantName $config.sourceTenant.tenantname -clientId $config.sourceTenant.clientId -clientSecret $config.sourceTenant.clientSecret
        $global:GraphHeaders = msGraphAuthenticate -tenantName $config.sourceTenant.tenantname -clientId $config.sourceTenant.clientId -clientSecret $config.sourceTenant.clientSecret
}

# FUNCTION: generatePassword
# DESCRIPTION: Generates a random password.
# PARAMETERS: $length - The length of the password to generate.
function generatePassword() {
        Param(
                [int]$length = 12
        )
        $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',<.>/?"
        $securePassword = New-Object -TypeName System.Security.SecureString
        1..$length | ForEach-Object {
                $random = $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)]
                $securePassword.AppendChar($random)
        }
        return $securePassword
}
    

function msMonitorAuthenticate() {
        [CmdletBinding()]
        Param(
                [Parameter(Mandatory = $true)]
                [string]$tenantName,
                [Parameter(Mandatory = $true)]
                [string]$clientId,
                [Parameter(Mandatory = $true)]
                [string]$clientSecret
        )
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/x-www-form-urlencoded")
        $body = "grant_type=client_credentials&scope=https://monitor.azure.com//.default"
        $body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)
        $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body
        # Get token from OAuth response
    
        $token = -join ("Bearer ", $response.access_token)
    
        # Reinstantiate headers
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $token)
        $headers.Add("Content-Type", "application/json")
        $headers = @{'Authorization' = "$($token)" }
        return $headers
}

function msGraphAuthenticate() {
        [CmdletBinding()]
        Param(
                [Parameter(Mandatory = $true)]
                [string]$tenantName,
                [Parameter(Mandatory = $true)]
                [string]$clientId,
                [Parameter(Mandatory = $true)]
                [string]$clientSecret
        )
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/x-www-form-urlencoded")
        $body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
        $body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)
        $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body
        # Get token from OAuth response
    
        $token = -join ("Bearer ", $response.access_token)
    
        # Reinstantiate headers
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $token)
        $headers.Add("Content-Type", "application/json")
        $headers = @{'Authorization' = "$($token)" }
        return $headers
}

function Write-Log {
        <#
        .SYNOPSIS
        This function writes a report to Write-Log Analytics.
    
        .DESCRIPTION
        The function collects various statistics about the runbook execution, such as the runbook name, day of the week, number of errors, warnings, changes, and the runtime in minutes. It then writes these statistics to a custom Write-Log Analytics table.
    
        .PARAMETER None
        This function does not accept any parameters.
    
        .EXAMPLE
        Write-ReportToLogAnalytics
    
        This example calls the function to write a report to Write-Log Analytics.
    
        .NOTES
        This function relies on several global variables, including $RunbookName, $AllErrors, $AllWarnings, $AllChanges, and $ScriptRuntimeCalculation. Make sure these variables are properly initialized before calling this function.
        #>
        [CmdletBinding()]
        param (                
                [Parameter(Mandatory = $true)] 
                [string]$Message,
                [ValidateSet("Output", "Warning", "Verbose", "Error")]
                [Parameter(Mandatory = $false)]
                [string]$LogLevel = "Output"

        )
    
        try {    
    
                # Get the device name directly from PowerShell
                $deviceName = $env:COMPUTERNAME
                $timestamp = (Get-Date).ToString("o")  # ISO 8601 format for consistency

                # Construct the Write-Log entry
                $logEntry = @{
                        TimeGenerated = $timestamp
                        Level         = $LogLevel
                        Message       = $Message
                        DeviceName    = $deviceName  # Include device name in the Write-Log entry
                }
    
                Write-Verbose 'Sending statistics to AutomationJobReport custom table'
                Write-LogAnalyticsCustomWrite-Log -LogEntry $LogEntry
                if ($LogLevel -eq "Output") {
                        Write-Output $Message
                }
                elseif ($LogLevel -eq "Error") {
                        Write-Error $Message
                }
                elseif ($LogLevel -eq "Warning") {
                        Write-Warning $Message
                }
                elseif ($LogLevel -eq "Verbose") {
                        Write-Verbose $Message
                }
             
        }
        catch {
                Write-Error 'Error occured while reporting job to Write-Log Analytics Workspace'
        }
}

function Write-LogAnalyticsCustomWrite-Log {
        <#
        .SYNOPSIS
        Writes a Write-Log entry to a custom Write-Log in Write-Log Analytics.
    
        .DESCRIPTION
        This function sends a Write-Log entry to a custom Write-Log in Write-Log Analytics. The custom Write-Log needs to be created in Write-Log Analytics before using this function.
    
        .PARAMETER LogEntry
        The Write-Log entry to be written to the custom log. This should be an object that can be converted to JSON.
    
        .PARAMETER LogName
        The name of the custom log. If the name does not end with '_CL', the suffix will be added automatically.
    
        .PARAMETER LogAnalyticsDcrImmutableId
        The ID of the Write-Log Analytics data collection rule. If not provided, the function will attempt to retrieve it from an automation variable named 'LogAnalyticsDcrImmutableId'.
    
        .PARAMETER LogAnalyticsDceEndpoint
        The URL of the Write-Log Analytics data collector endpoint. If not provided, the function will attempt to retrieve it from an automation variable named 'LogAnalyticsDceEndpoint'.
    
        .EXAMPLE
        Write-LogAnalyticsCustomWrite-Log -LogEntry $Array -LogName "SpokeUsageAlerts_CL" 
        Writes a Write-Log entry to the custom Write-Log 'SpokeUsageAlerts_CL' in Write-Log Analytics.
    
        .EXAMPLE
        Write-LogAnalyticsCustomWrite-Log -LogEntry $Array -LogName "SpokeUsageAlerts" -LogAnalyticsDcrImmutableId "dcr-3aae6cdc4294453aa457ec7720f43040" -LogAnalyticsDceEndpoint "https://platformscriptloganalyticsworkspace-dce-7myy.northeurope-1.ingest.monitor.azure.com"
        Writes a Write-Log entry to the custom Write-Log 'SpokeUsageAlerts_CL' in Write-Log Analytics using the specified data collection rule ID and data collector endpoint.
        #>
    
        [CmdletBinding(
        )]
    
        param(
                [Parameter(Mandatory = $true)]
                $LogEntry,
                [Parameter(Mandatory = $false)]
                [string]
                $LogName = $config.logAnalytics.logName,
                [Parameter(Mandatory = $false)]
                [string]$LogAnalyticsDcrImmutableId = $config.logAnalytics.DcrImmutableId,
                [Parameter(Mandatory = $false)]
                [string]$LogAnalyticsDceEndpoint = $config.logAnalytics.DceEndpoint
        )
    
        try {
    
                # Check if LogEntry is a string and convert to JSON if not
                if ($LogEntry.GetType().Name -ne "String") {
                        $LogEntry = $LogEntry | ConvertTo-Json
                }
            
                # We are making sure that the JSON is formatted as an array
                $JsonObject = $LogEntry | ConvertFrom-Json
                $Body = ConvertTo-Json @($JsonObject)
    
                # Check if LogName contains '_CL'
                if ($LogName -notmatch "_CL") {
                        Write-Warning -Message "LogName does not contain '_CL'. Adding '_CL' to LogName"
                        $LogName = $LogName + "_CL"
                }
    
                Add-Type -AssemblyName System.Web
    
                $headers = @{"Authorization" = $monitorHeaders.Authorization; "Content-Type" = "application/json" }
                $uri = "$LogAnalyticsDceEndpoint/dataCollectionRules/$LogAnalyticsDcrImmutableId/streams/Custom-$LogName" + "?api-version=2023-01-01"
                Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers
    
                Write-Verbose "Successfully wrote LogEntry to Write-Log Analytics Workspace into CustomWrite-Log $LogName"
        }
        catch {
                Write-Error "Error occured while writing to Write-Log Analytics $_"
        }
}
    


# FUNCTION: exitScript
# DESCRIPTION: Exits the script with error code and takes action depending on the error code.
function exitScript() {
        [Cmdletbinding()]
        Param(
                [Parameter(Mandatory = $true)]
                [int]$exitCode,
                [Parameter(Mandatory = $true)]
                [string]$functionName,
                [array]$tasks = @("reboot", "postMigrate")
        )
        if ($exitCode -eq 1) {
                Write-Log "Exiting script with critical error on $($functionName)."
                Write-Log "Disabling tasks..."
                foreach ($x in $tasks) {
                        $task = Get-ScheduledTask -TaskName $x -ErrorAction SilentlyContinue
                        if ($task) {
                                Disable-ScheduledTask -TaskName $x -Verbose
                                Write-Log "Disabled $($x) task."
                        }
                        else {
                                Write-Log "$($x) task not found."
                        }
                }
                Write-Log "Enabling password logon provider..."
                reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /v "Disabled" /t REG_DWORD /d 0 /f | Out-Host
                Write-Log "Enabled logon provider."
                Write-Log "Exiting script... please reboot device."
                Stop-Transcript
                exit 1
        }
        else {
                Write-Log "Migration script failed.  Review logs at C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
                Write-Log "Disabling tasks..."
                foreach ($x in $tasks) {
                        $task = Get-ScheduledTask -TaskName $x -ErrorAction SilentlyContinue
                        if ($task) {
                                Disable-ScheduledTask -TaskName $x -Verbose
                                Write-Log "Disabled $($x) task."
                        }
                        else {
                                Write-Log "$($x) task not found."
                        }
                }
                Write-Log "Exiting script."
                exit 0
        }
}
    

function Wait-ForInternetConnection {
        param (
                [string]$Target = "google.com", # Default target to check connectivity
                [string]$DNSServer = "8.8.8.8", # Default DNS server to use for resolution
                [int]$TimeoutSeconds = 60, # Maximum wait time in seconds
                [int]$CheckIntervalSeconds = 5         # Interval between checks in seconds
        )
    
        $elapsedTime = 0
    
        # Loop until a successful ping or timeout
        while ($elapsedTime -lt $TimeoutSeconds) {
                try {
                        # Attempt to ping the target
                        try {
                                $dnsResult = Resolve-DnsName -Name $Target -Server $DNSServer -ErrorAction Stop
                                Write-Log "Internet connection is available."
                                return $true

                        }
                        catch {
                                Write-Log "No internet connection detected. Waiting..."
                        }
                }
                catch {
                        Write-Log "Error during connection check: $_"
                }
    
                # Wait for the specified interval before checking again
                Start-Sleep -Seconds $CheckIntervalSeconds
                $elapsedTime += $CheckIntervalSeconds
        }
        return $false
}