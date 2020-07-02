# BeRoot For Windows

BeRoot(s) is a post exploitation tool to check common Windows misconfigurations to find a way to escalate our privilege. \
A compiled version is available [here](https://github.com/AlessandroZ/BeRoot/releases). 

It has been added to the [pupy](https://github.com/n1nj4sec/pupy/) project as a post exploitation module (it's executed in memory without touching the disk). 

This tool is only used to detect and not to exploit. If something is found, [templates](https://github.com/AlessandroZ/BeRoot/tree/master/Windows/templates) could be used to exploit it. To use it, just create a __test.bat__ file located next to the service / DLL used. It should execute it once called. Depending on the Redistributable Packages installed on the target host, these binaries may not work.  

Run it
----
```
|====================================================================|
|                                                                    |
|                    Windows Privilege Escalation                    |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


usage: beRoot.exe [-h] [-l]

Windows Privilege Escalation

optional arguments:
  -h, --help         show this help message and exit
  -l, --list         list all softwares installed (not run by default)
```

All detection methods are described on the following document. 


Path containing space without quotes
----

Consider the following file path: 
```
C:\Program Files\Some Test\binary.exe
```

If the path contains spaces and no quotes, Windows would try to locate and execute programs in the following order:
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\binary.exe
```

Following this example, if "_C:\\_" folder is writable, it would be possible to create a malicious executable binary called "_Program.exe_". If "_binary.exe_" run with high privilege, it could be a good way to escalate our privilege.

Note: BeRoot realized these checks on every service path, scheduled tasks and startup keys located in HKLM.

__How to exploit__: \
\
The vulnerable path runs as: 
* _a service_: create a malicious service (or compile the service template)
* _a classic executable_: Create your own executable. 

Writable directory
----

Consider the following file path:
```
C:\Program Files\Some Test\binary.exe
```

If the root directory of "_binary.exe_" is writable (_"C:\Program Files\Some Test\"_) and run with high privilege, it could be used to elevate our privileges. 

__Note__: BeRoot realized these checks on every service path, scheduled tasks and startup keys located in HKLM.

__How to exploit__:
* The service is not running:
	* Replace the legitimate service by our own, restart it or check how it's triggered (at reboot, when another process is started, etc.).

* The service is running and could not be stopped:
	* Most exploitation will be like that, checks for dll hijacking and try to restart the service using previous technics.


Writable directory on %PATH%
----

This technic affects the following Windows version:
```
6.0 	=> 	Windows Vista / Windows Server 2008
6.1 	=> 	Windows 7 / Windows Server 2008 R2
6.2 	=> 	Windows 8 / Windows Server 2012
```

On a classic Windows installation, when DLLs are loaded by a binary, Windows would try to locate it using these following steps:
```
- Directory where the binary is located
- C:\Windows\System32
- C:\Windows\System
- C:\Windows\
- Current directory where the binary has been launched
- Directory present in %PATH% environment variable
```

If a directory on the __%PATH%__ variable is writable, it would be possible to realize DLL hijacking attacks. Then, the goal would be to find a service which loads a DLL not present on each of these path. This is the case of the default "__IKEEXT__" service which loads the inexistant "__wlbsctrl.dll__". 

__How to exploit__: Create a malicious DLL called "_wlbsctrl.dll_" (use the [DLL template](https://github.com/AlessandroZ/BeRoot/tree/master/templates/DLL_Hijacking)) and add it to the writable path listed on the %PATH% variable. Start the service "_IKEEXT_".
To start the IKEEXT service without high privilege, a technic describe on the french magazine MISC 90 explains the following method: 

Create a file as following: 
```
C:\Users\bob\Desktop>type test.txt
[IKEEXTPOC]
MEDIA=rastapi
Port=VPN2-0
Device=Wan Miniport (IKEv2)
DEVICE=vpn
PhoneNumber=127.0.0.1
```

Use the "_rasdial_" binary to start the IKEEXT service. Even if the connection failed, the service should have been started. 
```
C:\Users\bob\Desktop>rasdial IKEEXTPOC test test /PHONEBOOK:test.txt
```
Or you can try using these tools: 
* [Ikeext-Privesc](https://github.com/itm4n/Ikeext-Privesc) powershell script
* [Wlbsctrl_poc](https://github.com/djhohnstein/wlbsctrl_poc) in C++


AlwaysInstallElevated registry key
----

__AlwaysInstallElevated__ is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (_MSI_) with elevated (_SYSTEM_) permissions. To allow it, two registry entries have to be set to __1__:
```
HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

__How to exploit__: create a malicious msi binary and execute it. 

Unattended Install files
----

This file contains all the configuration settings that were set during the installation process, some of which can include the configuration of local accounts including Administrator accounts.
These files are available on these following path: 
```
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\unattend.xml 
C:\Windows\System32\Sysprep\Panther\unattend.xml
```

__How to exploit__: open the unattend.xml file to check if passwords are present on it. 
Should looks like: 
```
<UserAccounts>
    <LocalAccounts>
        <LocalAccount>
            <Password>
                <Value>RmFrZVBhc3N3MHJk</Value>
                <PlainText>false</PlainText>
            </Password>
            <Description>Local Administrator</Description>
            <DisplayName>Administrator</DisplayName>
            <Group>Administrators</Group>
            <Name>Administrator</Name>
        </LocalAccount>
    </LocalAccounts>
</UserAccounts>
```

Services
----

Checks if it's possible to: 
* Modify an existing service
* Create a new service

*Note: Checks on path are performed on all services ("Path containing space without quotes" and "Writable directory")*

Tasks Scheduler
----

Check if it's possible to modify the directory where all scheduled tasks are stored: "_C:\Windows\system32\Tasks_"

*Note: Checks on path are performed on all scheduled tasks ("Path containing space without quotes" and "Writable directory")*


Startup Key
----

Check if it's possible to modify a startup key (on HKLM)

*Note: Checks on path are performed on all startup keys ("Path containing space without quotes" and "Writable directory")*


Windows Privileges & Tokens
----

Thanks to __Andrea Pierini__'s work, some interesting Windows privileges could be used to escalate privileges. 
These privileges are: 
* SeDebug
* SeRestore & SeBackup & SeTakeOwnership
* SeTcb & SeCreateToken
* SeLoadDriver
* SeImpersonate & SeAssignPrimaryToken 

Beroot lists all privileges we have and highlight if we have one of these tokens.

__How to exploit__: Everything is well explained on __Andrea Pierini__'s [pdf](https://github.com/AlessandroZ/BeRoot/blob/master/Windows/templates/RomHack%202018%20-%20Andrea%20Pierini%20-%20whoami%20priv%20-%20show%20me%20your%20Windows%20privileges%20and%20I%20will%20lead%20you%20to%20SYSTEM.pdf). 


Local account with's empty password
----

All local accounts are tested to detect empty password. 

Local account with passwordreq:no
----

Idea comes from 0xRick 's [write up](https://0xrick.github.io/hack-the-box/access/).

Checking for user account options, we could see this kind of output: 

```
> net user username
....
Password Required   No
...
```
This means than the option `/passwordreq:no` has been set
```
> net user /passwordreq:no username
```

This directive allows us to use `runas` without needed the user account password. 

```
> runas /user:username /savecred cmd.exe
```

Check 0xRick blog post to have a better example.


Not managed by Beroot
----

Some misconfigurations that could lead to privilege escalation are not checked by Beroot. These actions need monitoring and should be done manually: 
* When a privilege account access a non privilege file: http://offsec.provadys.com/intro-to-file-operation-abuse-on-Windows.html
* Dll Hijacking
* Outdated Windows (use [Watson](https://github.com/rasta-mouse/Watson) or [wesng](https://github.com/bitsadmin/wesng) and check on [github](https://github.com/SecWiki/windows-kernel-exploits) for exploits).
* From Local/Network service account to admin. Check itm4n's [write up](https://itm4n.github.io/localservice-privileges/) and his [tool](https://github.com/itm4n/FullPowers) 

Special thanks
----
* Good description of each checks: https://toshellandback.com/2015/11/24/ms-priv-esc/
* Andrea Pierini [work](https://2018.romhack.io/slides/RomHack%202018%20-%20Andrea%20Pierini%20-%20whoami%20priv%20-%20show%20me%20your%20Windows%20privileges%20and%20I%20will%20lead%20you%20to%20SYSTEM.pdf)
