<#
	.SYNOPSIS
		Updates SensorGroupingTags when sensor removal protection is enabled.
		Retrieves maintenance token and updates the Falcon Sensor tags on a Windows host using CSSensorSettings.exe
		This version is hard-coded to the US-1 API destination (https://api.crowdstrike.com). Be sure to update if
		your CID is in another region.

	.NOTES
		Author(s): nckpi
		Usage: Use at your own discretion. While efforts have been made to ensure this script works as expected, 
		you should test in your own environment. This script uses a sensitive API scope which could allow bypass of sensor 
		security controls. Availability of API keys should be always be controlled.
		
		The ValidateSet $TagGroup is a template one can modify to prepare ready-made Grouping Tags to be specified by a single word at runtime.

		Run locally, the script would be executed with a command structure of:
		SensorSettingsChange.ps1 -ClientID [API ID] -ClientSecret [API secret] -TagGroup [ValidateSet]

		This script can be uploaded to RTR Scripts and executed from Falcon RTR with a command like:
		runscript -CloudFile="SensorGroupingTagUpdate" -CommandLine="-ClientID [API ID] -ClientSecret [API secret] -TagGroup [ValidateSet]"
		(CloudFile name is the name you give it in the console)
		Always test on hosts for yourself before committing to any mass scale.
		
		ClientID refers to the API Client ID you create on the 'API Clients and Keys' page. ClientSecret refers to the API key secret

	Requirements:
	Falcon Administrator role required to create API access
	PowerShell v3 or higher
	TLS 1.2 minimum
	API Client scope 'Sensor Update Policies: Write'
	Target host must have Falcon sensor for Windows 6.42 or later for the CsSensorSettings.exe to be present

	.DESCRIPTION
		Change the Sensor Tags using PowerShell via an automation process.
		Privileged escalation of powershell required.
		Uninstallation token is obtained via reveal-uninstall-token API call to the source cloud.
  
	.PARAMETER ClientId
		OAuth2 API Client Id from the cloud tenant. Required to pull unique maintenance token.
  
	.PARAMETER ClientSecret
		OAuth2 API Client Secret from the cloud tenant. Required to pull unique maintenance token.

	.PARAMETER AuditMessage
		Add a custom message for audit records in the Falcon UI. Modify a needed.
	
	.PARAMETER LogDest
		Specify destination file for transcript log. e.g., 'c:\temp\CSUninstall.log'
		Related commands may be commented out if no local log file is desired.

<# -------------------	  Begin Editable Region. -------------- #>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]
	$ClientId = '',
 
	[Parameter(Mandatory = $true)]
	[string]
	$ClientSecret = '',
	
	[Parameter(Mandatory = $false)]
	[string]
	$AuditMessage = 'Setting Sensor Tags',

    [ValidateSet('Desktops', 'Servers', 'Laptops')]
    [string]
    $TagGroup = '',
	
	[Parameter(Mandatory = $false)]
	[string]
	$LogDest = 'C:\Temp\CSSensorSettingsChange.log'
)
<# ----------------	  END Editable Region. ----------------- #>
begin {
	# Start-Transcript -Path $LogDest -IncludeInvocationHeader
	# Uncomment Start-Transcript above and Stop-Transcript at end if you want to generate a log file of scripts events or errors on the target host
	# As is, the transcript will overwrite a previous file with the same name.
	# If you want multiple runs of the script to keep logging events in a single running file, then add the -Append option
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	# Offer list of grouping tags which can be selected at script runtime as a parameter
    switch ($TagGroup) {
        'Desktops' { $Tags = 'businessunit,workstation,thoseguys' }
        'Servers' { $Tags = 'Prod,Server,PatchMe' }
        'Laptops' { $Tags = 'Sales' }
    }

	function Request-Token {
		# Validate if API credentials have been set.
		if ((-not $ClientId) -or (-not $ClientSecret)) {
			Write-Host "API credentials not configured properly. Cancelling token request attempt."
			Return
		}

		# Get HostId value from registry
		$HostId = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\" +
		"{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}" +
		"\Default") -Name AG).AG)).ToLower() -replace '-','')

		# Validate HostID is found in Registry
		if (-not $HostId) {
			Write-Host "Unable to retrieve host identifier. Cancelling token request attempt."
			Return
		}

		$Param = @{
			Uri = "https://api.crowdstrike.com/oauth2/token"
			Method = 'post'
			Headers = @{
				accept = 'application/json'
				'content-type' = 'application/x-www-form-urlencoded'
			}
			Body = @{
				'client_id' = $ClientId
				'client_secret' = $ClientSecret
			}
		}

		# Get API Token and build API request
		$ApiToken = try {
			(Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json
		}

		catch {
			if ($_.ErrorDetails) {
				$_.ErrorDetails | ConvertFrom-Json
			}
			else {
				$_.Exception
			}
		}

		if (-not $ApiToken.access_token) {
			if ($ApiToken.GetType().Name -eq "WebException") {
				Write-Host "Unable to request token from cloud US-1 using client id $($ClientId). Return was: $($ApiToken)"
				Break
			} else {
				Write-Host "Unable to request token from cloud US-1 using client id $($ClientId). Return error code: $($ApiToken.errors.code). Return error message: $($ApiToken.errors.message)"
				Break
			}
		}

		$Param = @{
			Uri = "https://api.crowdstrike.com/policy/combined/reveal-uninstall-token/v1"
			Method = 'post'
			Headers = @{
				accept = 'application/json'
				'content-type' = 'application/json'
				authorization = "$($ApiToken.token_type) $($ApiToken.access_token)"
			}
			Body = @{
				audit_message = $AuditMessage
				device_id = $HostId
			} | ConvertTo-Json
		}

		# Get sensor maintenance token
		$script:Request = try {
			Invoke-WebRequest @Param -UseBasicParsing | ConvertFrom-Json
		}

		catch {
			if ($_.ErrorDetails) {
				$_.ErrorDetails | ConvertFrom-Json
			}
			else {
				$_.Exception
			}
		}

		if (-not $Request.resources) {
			Write-Host "Unable to retrieve maintenance token by API"
		}
	}

    # Function to change the tags. Edit your grouping tags at will.
	# Or make it a parameter to select different sets of tags at runtime.
	function Invoke-CSSensorSettings {
		Request-Token
		if ((-not $ClientId) -or (-not $ClientSecret)) {
			Write-Host "Skipping API call for unique token retrieval. Please check your ClientId and Secret if one was entered."
			Return
			}
		$MaintToken = $script:Request.resources.uninstall_token
		# Change path to directory containing CSSensorSettings.exe
        Set-Location 'C:\Program Files\CrowdStrike'
        $MaintToken | .\CSSensorSettings.exe set --grouping-tags "$Tags"
		}
	}

process {
	Invoke-CSSensorSettings
	Write-Output 'Script execution complete'
}

end {
	#Stop-Transcript
}