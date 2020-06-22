### POWERSHELL SCAN

##### PORT SCAN
```powershell
Import-Module Invoke-Portscan.ps1
<#
Invoke-Portscan -Hosts "websrv.domain.local,wsus.domain.local,apps.domain.local" -TopPorts 50
echo websrv.domain.local | Invoke-Portscan -oG test.gnmap -f -ports "80,443,8080"
Invoke-Portscan -Hosts 172.16.0.0/24 -T 4 -TopPorts 25 -oA localnet
#>
```

### AD MODULE WITHOUT RSAT

The secret to being able to run AD enumeration commands from the AD Powershell module on a system without RSAT installed, is the DLL located in <b>C:\Windows\Microsoft\.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management</b> on a system that has the RSAT installed.

Set up your AD VM, install RSAT, extract the dll and drop it to the target system used to enumerate the active directory.

```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Get-Command get-adcom*
```

### GENERAL FUNCTIONS OF POWERVIEW

##### Misc Functions:
```powershell
Export-PowerViewCSV             #  thread-safe CSV append
Set-MacAttribute                #  Sets MAC attributes for a file based on another file or input (from Powersploit)
Copy-ClonedFile                 #  copies a local file to a remote location, matching MAC properties
Get-IPAddress                   #  resolves a hostname to an IP
Test-Server                     #  tests connectivity to a specified server
Convert-NameToSid               #  converts a given user/group name to a security identifier (SID)
Convert-SidToName               #  converts a security identifier (SID) to a group/user name
Convert-NT4toCanonical          #  converts a user/group NT4 name (i.e. dev/john) to canonical format
Get-Proxy                       #  enumerates local proxy settings
Get-PathAcl                     #  get the ACLs for a local/remote file path with optional group recursion
Get-UserProperty                #  returns all properties specified for users, or a set of user:prop names
Get-ComputerProperty            #  returns all properties specified for computers, or a set of computer:prop names
Find-InterestingFile            #  search a local or remote path for files with specific terms in the name
Invoke-CheckLocalAdminAccess    #  check if the current user context has local administrator access to a specified host
Get-DomainSearcher              #  builds a proper ADSI searcher object for a given domain
Get-ObjectAcl                   #  returns the ACLs associated with a specific active directory object
Add-ObjectAcl                   #  adds an ACL to a specified active directory object
Get-LastLoggedOn                #  return the last logged on user for a target host
Get-CachedRDPConnection         #  queries all saved RDP connection entries on a target host
Invoke-ACLScanner               #  enumerate -1000+ modifable ACLs on a specified domain
Get-GUIDMap                     #  returns a hash table of current GUIDs -> display names
Get-DomainSID                   #  return the SID for the specified domain
Invoke-ThreadedFunction         #  helper that wraps threaded invocation for other functions
```

##### net * Functions:
```powershell
Get-NetDomain                   #  gets the name of the current user's domain
Get-NetForest                   #  gets the forest associated with the current user's domain
Get-NetForestDomain             #  gets all domains for the current forest
Get-NetDomainController         #  gets the domain controllers for the current computer's domain
Get-NetUser                     #  returns all user objects, or the user specified (wildcard specifiable)
Add-NetUser                     #  adds a local or domain user
Get-NetComputer                 #  gets a list of all current servers in the domain
Get-NetPrinter                  #  gets an array of all current computers objects in a domain
Get-NetOU                       #  gets data for domain organization units
Get-NetSite                     #  gets current sites in a domain
Get-NetSubnet                   #  gets registered subnets for a domain
Get-NetGroup                    #  gets a list of all current groups in a domain
Get-NetGroupMember              #  gets a list of all current users in a specified domain group
Get-NetLocalGroup               #  gets the members of a localgroup on a remote host or hosts
Add-NetGroupUser                #  adds a local or domain user to a local or domain group
Get-NetFileServer               #  get a list of file servers used by current domain users
Get-DFSshare                    #  gets a list of all distribute file system shares on a domain
Get-NetShare                    #  gets share information for a specified server
Get-NetLoggedon                 #  gets users actively logged onto a specified server
Get-NetSession                  #  gets active sessions on a specified server
Get-NetRDPSession               #  gets active RDP sessions for a specified server (like qwinsta)
Get-NetProcess                  #  gets the remote processes and owners on a remote server
Get-UserEvent                   #  returns logon or TGT events from the event log for a specified host
Get-ADObject                    #  takes a domain SID and returns the user, group, or computer object associated with it
Set-ADObject                    #  takes a SID, name, or SamAccountName to query for a specified  domain object, and then sets a pecified 'PropertyName' to a specified 'PropertyValue'
```

##### GPO functions:
```powershell
Get-GptTmpl                     #  parses a GptTmpl.inf to a custom object
Get-NetGPO                      #  gets all current GPOs for a given domain
Get-NetGPOGroup                 #  gets all GPOs in a domain that set "Restricted Groups" on on target machines
Find-GPOLocation                #  takes a user/group and makes machines they have effectiverights over through GPO enumeration and correlation
Find-GPOComputerAdmin           #  takes a computer and determines who has admin rights over itthrough GPO enumeration
Get-DomainPolicy                #  returns the default domain or DC policy
```

##### User-Hunting Functions:
```powershell
Invoke-UserHunter               #  finds machines on the local domain where specified users are logged into, and can optionally check if the current user has local admin access to found machines
Invoke-StealthUserHunter        #  finds all file servers utilizes in user HomeDirectories, and checks the sessions one each file server, hunting for particular users
Invoke-ProcessHunter            #  hunts for processes with a specific name or owned by a specific user on domain machines
Invoke-UserEventHunter          #  hunts for user logon events in domain controller event logs
```
##### Domain Trust Functions:
```powershell
Get-NetDomainTrust              #  gets all trusts for the current user's domain
Get-NetForestTrust              #  gets all trusts for the forest associated with the current user's domain
Find-ForeignUser                #  enumerates users who are in groups outside of their principal domain
Find-ForeignGroup               #  enumerates all the members of a domain's groups and finds users that are outside of the queried domain
Invoke-MapDomainTrust           #  try to build a relational mapping of all domain trusts
```

##### MetaFunctions:
```powershell
Invoke-ShareFinder              #  finds (non-standard) shares on hosts in the local domain
Invoke-FileFinder               #  finds potentially sensitive files on hosts in the local domain
Find-LocalAdminAccess           #  finds machines on the domain that the current user has local admin access to
Find-ManagedSecurityGroups      #  searches for active directory security groups which are managed and identify users who have write access to
                                #  those groups (i.e. the ability to add or remove members)
Find-UserField                  #  searches a user field for a particular term
Find-ComputerField              #  searches a computer field for a particular term
Get-ExploitableSystem           #  finds systems likely vulnerable to common exploits
Invoke-EnumerateLocalAdmin      #  enumerates members of the local Administrators groups across all machines in the domain
```


[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)