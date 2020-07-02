## DOMAIN ENUMERATION

#### DOMAIN
- Get current domain
```powershell
Get-NetDomain (PowerView)
Get-ADDomain (ActiveDirectory Module)
```
- Get object of another domain
```powershell
Get-NetDomain -Domain domain.local
Get-ADDomain -Identity domain.local
```
- Get domain SID for the current domain
```powershell
Get-DomainSID
(Get-ADDomain).DomainSID
```
- Get domain policy for the current domain
```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
```
- Get domain policy for another domain
```powershell
(Get-DomainPolicy -domain domain.local)."system access"
```
- Get domain controllers for the current domain
```powershell
Get-NetDomainController
Get-ADDomainController
```
- Get domain controllers for another domain
```powershell
Get-NetDomainController -Domain domain.local
Get-ADDomainController -DomainName domain.local -Discover
```

---
#### NETUSER
- Get a list of users in the current domain
```powershell
Get-NetUser
Get-NetUser -Username student1
Get-NetUser | select -ExpandProperty samaccountname
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
```
- Get list of all properties for users in the current domain
```powershell
Get-UserProperty
Get-UserProperty -Properties pwdlastset
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```
- Search for a particular string in a user's attributes
```powershell
Find-UserField -SearchField Description -SearchTerm "built"
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

---
#### NETGROUP
- Get a list of computers in the current domain
```powershell
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
Get-ADComputer -Filter * | select Name Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *
```
- Get all the groups in the current domain
```powershell
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
```
- Get all groups containing the word "admin" in group name
```powershell
Get-NetGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```
- Get all the members of the Domain Admins group
```powershell
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain target.local
```
- Get the group membership for a user
```powershell
Get-NetGroup -UserName "john"
Get-ADPrincipalGroupMembership -Identity student1
```
- List all the local groups on a machine (needs administrator privs on non-dc machines)
```powershell
Get-NetLocalGroup -ComputerName DC01.enumme.local -ListGroups
```
- Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
```powershell
Get-NetLocalGroup -ComputerName DC01.enumme.local -Recurse
```

---
#### LOGGED
- Get actively logged users on a computer (needs local admin rights on the target)
```powershell
Get-NetLoggedon -ComputerName <servername>
```
- Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
```powershell
Get-LoggedonLocal -ComputerName DC01.enumme.local
```
- Get the last logged user on a computer (needs administrative rights and remote registry on the target)
```powershell
Get-LastLoggedOn -ComputerName <servername>
```

---
#### SHARE
- Find shares on hosts in current domain
```powershell
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose
```
- Find sensitive files on computers in the domain
```powershell
Invoke-FileFinder -Verbose
```
- Get all fileservers of the domain
```powershell
Get-NetFileServer
```

---
#### GPO
- Get list of GPO in current domain
```powershell
Get-NetGPO
Get-NetGPO -ComputerName DC01.enumme.local
Get-GPO -All (GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html (Provides RSoP)
```
- Enumerate ACLs for all the GPOs
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
```
- Enumerate Restricted Groups from GPO
```powershell
Get-NetGPOGroup -Verbose
```
- Enumerate GPOs where target user or group have interesting permissions
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match "target"}
```
- Membership of the Group "RDPUsers”
```powershell
Get-NetGroupMember -GroupName RDPUsers
```
- Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```powershell
Get-NetGPOGroup
```
- Get users which are in a local group of a machine using GPO
```powershell
Find-GPOComputerAdmin -Computername srv.enumme.local
```
- Get machines where the given user is member of a specific group
```powershell
Find-GPOLocation -UserName john -Verbose
```
- GPO applied on the target OU
```powershell
(Get-NetOU targetmachine -FullData).gplink[LDAP://cn={x-x-x-x-x},cn=policies,cn=system,DC=target,DC=domain,DC=local;0]
Get-NetGPO -ADSpath 'LDAP://cn={x-x-x-x-x},cn=policies,cn=system,DC=target,DC=domain,DC=local'
```

---
#### OU
- Get OUs in a domain
```powershell
Get-NetOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties *
```
- Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
```powershell
Get-NetGPO -GPOname "{x-x-x-x-x}"
Get-GPO -Guid x-x-x-x-x (GroupPolicy module)
```
- List all the computers in the target OU
```powershell
Get-NetOU targetcomputer | %{Get-NetComputer -ADSPath $_}
```

---
#### ACL

- Get the ACLs associated with the specified object
```powershell
Get-ObjectAcl -SamAccountName john -ResolveGUIDs
Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs -Verbose
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs -Verbose
```
- Get the ACLs associated with the specified prefix to be used for search
```powershell
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```
- We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs
```powershell
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=domain,DC=local').Access
```
- Get the ACLs associated with the specified LDAP path to be used for search
```powershell
Get-ObjectAcl -ADSpath "LDAP://CN=Domain
Admins,CN=Users,DC=domain,DC=local" -ResolveGUIDs -Verbose
```
- Search for interesting ACEs
```powershell
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "target"}
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "targetgroup"}
```
- Get the ACLs associated with the specified path
```powershell
Get-PathAcl -Path "\\DC01.domain.local\sysvol"
```

---
#### DOMAIN TRUSTS
- Get a list of all domain trusts for the current domain
```powershell
Get-NetDomainTrust
Get-NetForestDomain -Verbose
Get-NetDomainTrust -Domain fr.k71.test.local
Get-ADTrust
Get-ADTrust -Identity fr.k71.test.local
```
- Get details about the current forest
```powershell
Get-NetForest
Get-NetForest -Forest domain.local
Get-ADForest
Get-ADForest -Identity domain.local
```
- Get all domains in the current forest
```powershell
Get-NetForestDomain
Get-NetForestDomain -Forest domain.local
(Get-ADForest).Domains
```
- Map all the trusts of the domain.local forest
```powershell
Get-NetForestDomain -Verbose | Get-NetDomainTrust
```
- Get all global catalogs for the current forest
```powershell
Get-NetForestCatalog
Get-NetForestCatalog -Forest domain.local
Get-ADForest | select -ExpandProperty GlobalCatalogs
```
- Map trusts of a forest
```powershell
Get-NetForestTrust
Get-NetForestTrust -Forest domain.local
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```
- List external trusts
```powershell
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
```
if Bi-Directional trust we can extract information

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)