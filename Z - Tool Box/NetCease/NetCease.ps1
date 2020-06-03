param([switch]$Revert)

function IsAdministrator
{
    param()
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)   
}

function BackupRegistryValue
{
    param([string]$key, [string]$name)
    $backup = $name+'Backup'
    
    #Backup original Key value if needed
    $regKey = Get-Item -Path $key 
    $backupValue = $regKey.GetValue($backup, $null)
    $originalValue = $regKey.GetValue($name, $null)
    
    if (($backupValue -eq $null) -and ($originalValue -ne $null))
    {
        Set-ItemProperty -Path $key -Name $backup -Value $originalValue
    }

    return $originalValue
}

function RevertChanges
{
    param([string]$key,[string]$name)
    $backup = $name+'Backup'
    $regKey = Get-Item -Path $key

    #Backup original Key value if needed
    $backupValue = $regKey.GetValue($backup, $null)
    
    Write-Host "Reverting changes..."
    if ($backupValue -eq $null)
    {
        #Delete the value when no backed up value is found
        Write-Host "Backup value is missing. cannot revert changes"
    }
    elseif ($backupValue -ne $null)
    {
        Write-Verbose "Backup value: $backupValue"
        Set-ItemProperty -Path $key -Name $name -Value $backupValue
        Remove-ItemProperty -Path $key -Name $backup
    } 
      
    Write-Host "Revert completed"
}

if (-not (IsAdministrator))
{
    Write-Host "This script requires administrative rights, please run as administrator."
    exit
}

#NetSessionEnum SecurityDescriptor Registry Key 
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
$name = "SrvsvcSessionInfo"
$SRVSVC_SESSION_USER_INFO_GET = 0x00000001

Write-Host "NetCease 1.02 by Itai Grady (@ItaiGrady), Microsoft Advance Threat Analytics (ATA) Research Team, 2016"

if ($Revert)
{
    RevertChanges -key $key -name $name
    Write-Host "In order for the reverting to take effect, please restart the Server service"
    exit
}

#Backup original Key value if needed
$srvSvcSessionInfo = BackupRegistryValue -key $key -name $name

#Load the SecurityDescriptor
$csd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true,$false, $srvSvcSessionInfo,0

#Remove Authenticated Users Sid permission entry from its DiscretionaryAcl (DACL)
$authUsers = [System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid
$authUsersSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $authUsers, $null
$csd.DiscretionaryAcl.RemoveAccessSpecific([System.Security.AccessControl.AccessControlType]::Allow, $authUsersSid,$SRVSVC_SESSION_USER_INFO_GET, 0,0) 

#Add Access Control Entry permission for Interactive Logon Sid
$wkt = [System.Security.Principal.WellKnownSidType]::InteractiveSid
$interactiveUsers = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
$csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $interactiveUsers, $SRVSVC_SESSION_USER_INFO_GET,0,0)

#Add Access Control Entry permission for Service Logon Sid
$wkt = [System.Security.Principal.WellKnownSidType]::ServiceSid
$serviceLogins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
$csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $serviceLogins, $SRVSVC_SESSION_USER_INFO_GET,0,0)

#Add Access Control Entry permission for Batch Logon Sid
$wkt = [System.Security.Principal.WellKnownSidType]::BatchSid
$BatchLogins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
$csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $BatchLogins, $SRVSVC_SESSION_USER_INFO_GET,0,0)

#Update the SecurityDescriptor in the Registry with the updated DACL
$data = New-Object -TypeName System.Byte[] -ArgumentList $csd.BinaryLength
$csd.GetBinaryForm($data,0)
Set-ItemProperty -Path $key -Name $name -Value $data
Write-Host "Permissions successfully updated"
Write-Host "In order for the hardening to take effect, please restart the Server service"
