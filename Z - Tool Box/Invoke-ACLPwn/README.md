# Invoke-ACLpwn

Invoke-ACLpwn is a tool that automates the discovery and pwnage of ACLs in 
Active Directory that are unsafe configured. 

For background information, read the release blog: https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/

Invoke-ACLpwn is designed to run with integrated credentials as well as 
with specified network credentials. The script works by creating an export 
of all ACLs in the domain with SharpHound as well as the group membership of 
the user account that the tool is running under. If the user does not already 
have writeDACL permissions on the domain object, the tool will enumerate all 
ACEs of the ACL of the domain. Every identity in an ACE has an ACL of its own, 
which is added to the enumeration queue. If the identity is a group and the 
group has members, every group member is added to the enumeration queue as well.

It may take some time to calculate and parse every ACL, but could end up with
a "chain" that leads to domain administrative privilges in the target domain.


## Dependencies and installation
No installation is needed, however, in order to run Invoke-ACLpwn, a few
depedencies must be met:
* `.NET 3.5` or later
* `sharphound.exe`
* If you want to run DCsync, you need `mimikatz.exe` as well.

## Usage

Parameters:
```
    Required parameters:        
        SharpHoundLocation: location of sharphound.exe    

    Optional parameters:
        Domain            : FQDN of the target domain
        Username          : Username to authenticate with
        Password          : Password to authenticate with
        WhatIf            : Displays only the action the script intends to do. No exploitation.
                            Access as well as potential access will increase if the user account is added
                            to security groups, so the result of this switch may look incomplete.
        NoSecCleanup      : By default, the user will be removed from the ACL and the groups that were added during runtime when the script is finished. 
                            Setting this switch will leave that in tact.
        NoDCSync          : Will not run DCSync after all necessary steps have been taken
        userAccountToPwn  : User account to retrieve NTLM hash of. Only single user accounts supported now. Defaults to krbtgt account.
        logToFile         : Switch to write console output to file with the same name as script.
        mimiKatzLocation  : location of mimikatz.exe
```

Please note that specifying the mimikatz location is required unless the 
`-NoDCSync` switch is specified.

Example usage:

```Powershell
    ./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -NoDCSync
    ./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe
    ./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -userAccountToPwn 'Administrator'
    ./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -LogToFile
    ./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -NoSecCleanup
    ./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username 'testuser' -Domain 'xenoflux.local' -Password 'Welcome01!'
```

## About restoring ACLs and groupmemberships
If the `-NoSecCleanup` switch is not specified, the script will remove any
permission that was set by the script as well as group memberships. 





