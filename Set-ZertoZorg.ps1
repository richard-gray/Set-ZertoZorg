function Set-ZertoZorg {
    <#
.SYNOPSIS  
    PowerShell script to set Zerto ZORG ID of VPGs
.DESCRIPTION
    Powershell script that sets the Zerto ZORG ID of a VPG or group of VPGs based on VPG naming prefix
.NOTES
    Version:        0.1
    Author:         Richard Gray
    Twitter:        @goodgigs
    Github:         richard-gray
.LINK
    https://github.com/richard-gray/ZertoZorgUpdate
#>

    param (
        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Please provide the IP/FQDN of the ZVM Server'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(1,1)]
        [Alias('ZVM', 'IP')]
        [String[]] $Server,
        [Parameter(
            Position = 1,
            Mandatory = $false,
            HelpMessage = 'Please provide the Port of the ZVM Server if not using the default of 9669'
        )]
        [ValidateCount(1,1)]
        [String[]] $Port = "9669",
        [Parameter(
            Position = 2,
            Mandatory = $true,
            HelpMessage = 'Please provide creditials for Zerto'
        )]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty, 
        [Parameter(
            Position = 3,
            Mandatory = $true,
            HelpMessage = 'Please provide the VPG prefix or Full VPG Name which requires the ZORG to be changed'
        )]
        [ValidateCount(1,1)]
        [String[]] $VPGPrefix,
        [Parameter(
            Position = 4,
            Mandatory = $true,
            HelpMessage = 'Please provide the Zorg Name'
        )]
        [ValidateCount(1,1)]
        [String[]] $ZorgName
    )

    # Script Variables
    $User = $Credential.UserName
    $Password = $Credential.GetNetworkCredential().Password  

    # Fix for certificate issues
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # Set the base URL
    $baseURL = "https://" + $Server + ":" + $Port + "/v1/"

    # Setup API session
    $xZertoSessionURL = $baseURL + "session/add"
    $authInfo = ("{0}:{1}" -f $User, $Password)
    $authInfo = [System.Text.Encoding]::UTF8.GetBytes($authInfo)
    $authInfo = [System.Convert]::ToBase64String($authInfo)
    $headers = @{Authorization = ("Basic {0}" -f $authInfo) }
    $sessionBody = '{"AuthenticationMethod": "1"}'
    $ContentType = "application/JSON"
    $xZertoSessionResponse = Invoke-WebRequest -Uri $xZertoSessionURL -Headers $headers -Method POST -Body $sessionBody -ContentType $ContentType

    # Extract x-zerto-session and setup headers for use later
    $xZertoSession = $xZertoSessionResponse.headers.get_item("x-zerto-session")
    $zertosessionHeader = @{"x-zerto-session" = $xZertoSession; "Accept" = "application/JSON"; "Content-Type" = "application/JSON" }

    # Get all Zorgs and VPGs
    $Zorgs = Invoke-RestMethod -Uri ($BaseURL + "zorgs") -TimeoutSec 100 -Headers $zertosessionHeader -ContentType $ContentType -Method GET
    $Vpgs = Invoke-RestMethod -Uri ($BaseURL + "vpgs") -TimeoutSec 100 -Headers $zertosessionHeader -ContentType $ContentType -Method GET

    # Get the identifier of the Zorg of what we want to update
    $ZorgIdentifier = $Zorgs | where-object { $_.ZorgName -eq $ZorgName } | Select-Object ZorgIdentifier -ExpandProperty ZorgIdentifier

    # Filter the list of VPGs to ones which match the prefix and are not set with the correct Zorg
    $VPGsToUpdate = $vpgs | Where-Object { ($_.VpgName -like "$VPGPrefix*") -and ($_.Zorg.identifier -ne $ZorgIdentifier) } 

    # Cycle through each VPG in the filtered list
    $VPGsToUpdate | ForEach-Object {

        # POST to VPGSettings to setup settings container
        $VPGIdentifierBody = '{ 
		    "VpgIdentifier":"' + $_.VpgIdentifier + '"
        }'
        $VpgSettingsIdentifier = Invoke-RestMethod -Uri ($BaseURL + "vpgsettings") -TimeoutSec 100 -Headers $zertosessionHeader -ContentType $ContentType -Method POST -Body $VPGIdentifierBody  
    
        # PUT to VPGSettings to update VPG with new Zorg
        $VPGZorgBody = '{ 
		    "ZorgIdentifier":"' + $ZorgIdentifier + '"
	    }'
        $BasicPUT = Invoke-RestMethod -Uri ($BaseURL + "vpgsettings/$VpgSettingsIdentifier/basic") -Headers $zertosessionHeader -Method PUT -Body $VPGZorgBody 
    
        # POST to VPGSettings to commit settings
        $VpgSettingsUpdateCommitPOST = Invoke-RestMethod -Method Post -Uri ($BaseURL + "vpgSettings/$VpgSettingsIdentifier/commit") -ContentType $TypeJSON -Headers $zertosessionHeader -TimeoutSec 100 -Body '{}'
    
        # Write output and wait between cycles to not overwhelm ZVMs
        Write-Host "Updating $_.VpgName" -NoNewline
        1..3 | ForEach-Object { Write-Host "." -NoNewline; Start-Sleep -seconds 1 } 
        Write-host "Done"
    }
}
