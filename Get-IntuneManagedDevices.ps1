<#

.SYNOPSIS
    Get-IntuneManagedDevices PowerShell script.

.DESCRIPTION
    Get-IntuneManagedDevices.ps1 is a PowerShell script retrieves Azure AD users with their last sign in date.

.AUTHOR:
    Mohammad Zmaili

.EXAMPLE
    .\Get-IntuneManagedDevices.ps1
      Retrieves all Intune Managed devices.
 
#>

function Connect-AzureDevicelogin {
    [cmdletbinding()]
    param( 
        [Parameter()]
        $ClientID = '1950a258-227b-4e31-a9cf-717495945fc2',
        
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        $TenantID = 'common',
        
        [Parameter()]
        $Resource = "https://graph.microsoft.com/",
        
        # Timeout in seconds to wait for user to complete sign in process
        [Parameter(DontShow)]
        $Timeout = 1
        #$Timeout = 300
    )
try {
    $DeviceCodeRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
        Body   = @{
            resource  = $Resource
            client_id = $ClientId
            redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
    }
    $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
 
    # Copy device code to clipboard
    $DeviceCode = ($DeviceCodeRequest.message -split "code " | Select-Object -Last 1) -split " to authenticate."
    Set-Clipboard -Value $DeviceCode

    Write-Host ''
    Write-Host "Device code " -ForegroundColor Yellow -NoNewline
    Write-Host $DeviceCode -ForegroundColor Green -NoNewline
    Write-Host "has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the sign in, and close the window to proceed." -ForegroundColor Yellow
    Write-Host "Note: If 'Microsoft Graph Authentication' window didn't open,"($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1) -ForegroundColor gray
    $msg= "Device code $DeviceCode has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the signin, and close the window to proceed.`n                                 Note: If 'Microsoft Graph Authentication' window didn't open,"+($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1)
    #Write-Log -Message $msg

    # Open Authentication form window
    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
    $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 440; Height = 600; Url = "https://www.microsoft.com/devicelogin" }
    $web.Add_DocumentCompleted($DocComp)
    $web.DocumentText
    $form.Controls.Add($web)
    $form.Add_Shown({ $form.Activate() })
    $web.ScriptErrorsSuppressed = $true
    $form.AutoScaleMode = 'Dpi'
    $form.text = "Microsoft Graph Authentication"
    $form.ShowIcon = $False
    $form.AutoSizeMode = 'GrowAndShrink'
    $Form.StartPosition = 'CenterScreen'
    $form.ShowDialog() | Out-Null
        
    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        Body   = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            code       = $DeviceCodeRequest.device_code
            client_id  = $ClientId
        }
    }
    $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
        if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
            throw 'Login timed out, please try again.'
        }
        $TokenRequest = try {
            Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
        }
        catch {
            $Message = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($Message.error -ne "authorization_pending") {
                throw
            }
        }
        Start-Sleep -Seconds 1
    }
    Write-Output $TokenRequest.access_token
}
finally {
    try {
        Remove-Item -Path $TempPage.FullName -Force -ErrorAction Stop
        $TimeoutTimer.Stop()
    }
    catch {
        #Ignore errors here
    }
}
}

Function ConnecttoAzureAD{
    Write-Host ''
    Write-Host "Checking if there is a valid Access Token..." -ForegroundColor Yellow
    #Write-Log -Message "Checking if there is a valid Access Token..."
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/domains"
    $GraphResult=""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if($GraphResult.value.Count)
    {
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            #Write-Log -Message $msg

    }else{
        Write-Host "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
        #Write-Log -Message "There no valid Access Token, please sign-in to get an Access Token"
        $global:accesstoken = Connect-AzureDevicelogin
        ''
        if ($global:accesstoken.Length -ge 1){
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            #Write-Log -Message $msg
        }
    }

}


cls
'========================================================'
Write-Host '                   AzureAD Intune Devices                 ' -ForegroundColor Green 
'========================================================'

''

ConnecttoAzureAD

$headers = @{ 
        'Content-Type'  = "application\json"
        'Authorization' = "Bearer $global:accesstoken"
        }
$GraphLink =   Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices?`$filter= mdmAppID eq '0000000a-0000-0000-c000-000000000000'" -Headers $headers -Method Get

$AADDevices = $GraphLink.Value
$NextLink = $GraphLink.'@odata.nextLink'
While ($NextLink -ne $null)
{
    $GraphLink = Invoke-RestMethod -Uri $NextLink -Headers $headers -Method Get
    $NextLink = $GraphLink.'@odata.nextLink'
    $AADDevices += $GraphLink.Value
}

$ADDeviceRep =@()
foreach($AADDevice in $AADDevices){
    $ADDeviceRepobj = New-Object PSObject
    $ADDeviceRepobj | Add-Member NoteProperty -Name "Object ID" -Value $AADDevice.id
    $ADDeviceRepobj | Add-Member NoteProperty -Name "Device ID" -Value $AADDevice.deviceId
    $ADDeviceRepobj | Add-Member NoteProperty -Name "Display Name" -Value $AADDevice.displayName
    if ($AADDevice.accountEnabled){$ADDeviceRepobj | Add-Member NoteProperty -Name "Enabled" -Value "Yes"}else{$ADDeviceRepobj | Add-Member NoteProperty -Name "Enabled" -Value "No"}
    $ADDeviceRepobj | Add-Member NoteProperty -Name "Operating System" -Value $AADDevice.operatingSystem
    $ADDeviceRepobj | Add-Member NoteProperty -Name "Operating System Version" -Value $AADDevice.operatingSystemVersion
    if($AADDevice.trustType -eq "ServerAd"){$ADDeviceRepobj | Add-Member NoteProperty -Name "Join Type" -Value "Hybrid Azure AD joined"}
    elseif ($AADDevice.trustType -eq "Workplace"){$ADDeviceRepobj | Add-Member NoteProperty -Name "Join Type" -Value "Azure AD registered"}
    elseif ($AADDevice.trustType -eq "AzureAd"){$ADDeviceRepobj | Add-Member NoteProperty -Name "Join Type" -Value "Azure AD joined"}
    else{$ADDeviceRepobj | Add-Member NoteProperty -Name "Join Type" -Value "N/A"}
    if ($AADDevice.isManaged){$ADDeviceRepobj | Add-Member NoteProperty -Name "Managed" -Value "Yes"}else{$ADDeviceRepobj | Add-Member NoteProperty -Name "Managed" -Value "No"}
    if ($AADDevice.isCompliant){$ADDeviceRepobj | Add-Member NoteProperty -Name "Compliant" -Value "Yes"}else{$ADDeviceRepobj | Add-Member NoteProperty -Name "Compliant" -Value "No"}
    if ($AADDevice.onPremisesSyncEnabled){$ADDeviceRepobj | Add-Member NoteProperty -Name "onPremisesSyncEnabled" -Value "Yes"}else{$ADDeviceRepobj | Add-Member NoteProperty -Name "onPremisesSyncEnabled" -Value "No"}
    $ADDeviceRepobj | Add-Member NoteProperty -Name "Created DateTime (UTC)" -Value $AADDevice.createdDateTime
    if ($AADDevice.approximateLastSignInDateTime) {$ADDeviceRepobj | Add-Member NoteProperty -Name "Last Success Signin (UTC)" -Value $AADDevice.approximateLastSignInDateTime}else{$ADDeviceRepobj | Add-Member NoteProperty -Name "Last Success Signin (UTC)" -Value "N/A"}
    $ADDeviceRep += $ADDeviceRepobj
}

$Date=("{0:s}" -f (get-date)).Split("T")[0] -replace "-", ""
$Time=("{0:s}" -f (get-date)).Split("T")[1] -replace ":", ""
$filerep = "IntuneManagedDevices_" + $Date + $Time + ".csv"
try{
    $ADDeviceRep | Export-Csv -path $filerep -NoTypeInformation
}catch{
    Write-Host ''
    Write-Host ''
    Write-Host "Operation aborted. Please make sure you have write permission on to write CSV file." -ForegroundColor red -BackgroundColor Black
    Write-Host ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    Write-Host ''
    exit
}

''
Write-Host "====================================="
Write-Host "|Retreived Azure AD Devices Summary:|"
Write-Host "====================================="
Write-Host "Number of retreived AAD Devices:" $AADDevices.Count

#$AADDevices | Group-Object operatingSystem | Sort-Object count | Select-Object Name, Count
''

$loc=Get-Location
Write-host $filerep "report has been created under the path:" $loc -ForegroundColor green

''
''
Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
''