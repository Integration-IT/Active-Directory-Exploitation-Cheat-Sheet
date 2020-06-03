@echo off

:: accesschk.exe from Sysinternals - mandatory executable, needed by this script
:: Listdlls.exe and pipelist.exe from Sysinternals - optional executables, few checks use them

:: set the mode - full or lhf (low hanging fruits)
set mode=lhf

:: if long execution checks should be done
set long=no

setlocal EnableDelayedExpansion

if [%1]==[] (
	echo.
	echo Usage:
	echo %0 "Users group name" ["Next group name"]
	echo.
	echo Example:
	echo %0 Users Everyone ^> ./output.txt
	goto :finish
)

REG ADD "HKCU\Software\Sysinternals\AccessChk" /v EulaAccepted /t REG_DWORD /d 1 /f > NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\ListDLLs" /v EulaAccepted /t REG_DWORD /d 1 /f > NUL 2>&1
REG ADD "HKCU\Software\Sysinternals\PipeList" /v EulaAccepted /t REG_DWORD /d 1 /f > NUL 2>&1

if "%mode%" NEQ "lhf" (goto :full)

echo Date of last applied patch - just use public exploits if not patched:
for /f %%a in ('wmic qfe get InstalledOn') do (
   set "var=%%a"
   for /f "tokens=1-3 delims=/" %%b in ("!var!") do set "aaa%%d%%b%%c=%%a"
)
for /f "tokens=1,* delims==" %%x in ('set aaa^| findstr /v /l /c:"InstalledOn"^|sort /r') do (
	echo %%y
	goto :eol
)
:eol

echo.
echo.

echo Files that may contain Administrator password - you know what to do with this one:
if exist %SystemDrive%\sysprep.inf echo %SystemDrive%\sysprep.inf 2>NUL
if exist %SystemDrive%\sysprep\sysprep.xml echo %SystemDrive%\sysprep\sysprep.xml 2>NUL
if exist %WINDIR%\system32\sysprep\Unattend.xml echo %WINDIR%\system32\sysprep\Unattend.xml 2>NUL
if exist %WINDIR%\system32\sysprep\Panther\Unattend.xml echo %WINDIR%\system32\sysprep\Panther\Unattend.xml 2>NUL
if exist "%WINDIR%\Panther\Unattend\Unattended.xml" echo "%WINDIR%\Panther\Unattend\Unattended.xml" 2>NUL
if exist "%WINDIR%\Panther\Unattended.xml" echo "%WINDIR%\Panther\Unattended.xml" 2>NUL
if exist "%WINDIR%\Panther\Unattend\Unattend.xml" echo "%WINDIR%\Panther\Unattend\Unattend.xml" 2>NUL
if exist "%WINDIR%\Panther\Unattend.xml" echo "%WINDIR%\Panther\Unattend.xml" 2>NUL
if exist %SystemDrive%\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT echo %SystemDrive%\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT 2>NUL
if exist %WINDIR%\panther\setupinfo echo %WINDIR%\panther\setupinfo 2>NUL
if exist %WINDIR%\panther\setupinfo.bak echo %WINDIR%\panther\setupinfo.bak 2>NUL
if exist %SystemDrive%\unattend.xml echo %SystemDrive%\unattend.xml 2>NUL
if exist %WINDIR%\system32\sysprep.inf echo %WINDIR%\system32\sysprep.inf 2>NUL
if exist %WINDIR%\system32\sysprep\sysprep.xml echo %WINDIR%\system32\sysprep\sysprep.xml 2>NUL
if exist %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config echo %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>NUL
if exist %SystemDrive%\inetpub\wwwroot\web.config echo %SystemDrive%\inetpub\wwwroot\web.config 2>NUL
if exist "%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml" echo "%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml" 2>NUL
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password 2>NUL
reg query HKCU\Software\SimonTatham\PuTTY\Sessions 2>NUL

echo.
echo.

echo Checking AlwaysInstallElevated - install *.msi files as NT AUTHORITY\SYSTEM - exploit/windows/local/always_install_elevated:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>NUL
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>NUL

echo.
echo.

echo.
echo.

echo Checking privileges - rotten potato:
whoami /priv | findstr /i /C:"SeImpersonatePrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivilege"

echo.
echo.

echo Checking if WSUS uses HTTP - eg. WSUXploit:
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ | find /i "wuserver" | find /i "http://"

echo.
echo.

echo Services with space in path and not enclosed with quotes - if you have permissions run executable from different directory - exploit/windows/local/trusted_service_path:
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows" ^| findstr /v /c:""""') do (
		echo %%~s | findstr /r /c:"^ .* .* .*$" >nul 2>&1 && (echo %%~s)
	)
)

echo.
echo.

echo Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading:
if exist C:\Windows\CCM\SCClient.exe (
    echo Installed.
) else (
    echo Not Installed.
)

echo.
echo.

for %%k in (%*) do (

	echo -----------------------------------------------------
	echo.
	echo Checking possibly weak permissions for %%~k group:
	echo.

	echo Services and their registries permissions - change BINARY_PATH_NAME of a service or path to the binary in the registry:
	accesschk.exe -accepteula -uwcqv %%k * | findstr /v /l /i /c:"No matching objects found."
	accesschk.exe -accepteula -kvuqsw %%k hklm\System\CurrentControlSet\services | findstr /v /l /i /c:"No matching objects found."

	echo.
	echo.
	
	echo Uninstall registries permissions - change binary paths:
	accesschk.exe -accepteula -kvuqsw %%k HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | findstr /v /l /i /c:"No matching objects found."

	echo.
	echo.

	echo System32 permissions - backdoor windows binaries:
	accesschk.exe -accepteula -dvuqw %%k "C:\Windows\system32" | findstr /v /l /i /c:"No matching objects found."
	accesschk.exe -accepteula -vuqsw %%k "C:\Windows\system32" | findstr /v /l /i /c:"No matching objects found."

	echo.
	echo.
	
	echo Windows Temp permissions - trying DLL Sideloading in each created directory:
	accesschk.exe -accepteula -dvuqr %%k "C:\Windows\system32" | findstr /v /l /i /c:"No matching objects found."
	
	echo.
	echo.
	
	echo Program Files permissions - backdoor windows binaries:
	accesschk.exe -accepteula -dvuqw %%k "%ProgramFiles%" | findstr /v /l /i /c:"No matching objects found."
	accesschk.exe -accepteula -vuqsw %%k "%ProgramFiles%" | findstr /v /l /i /c:"No matching objects found."
	accesschk.exe -accepteula -dvuqw %%k "%ProgramFiles(x86)%" | findstr /v /l /i /c:"No matching objects found."
	accesschk.exe -accepteula -vuqsw %%k "%ProgramFiles(x86)%" | findstr /v /l /i /c:"No matching objects found."

	echo.
	echo.

	echo PATH variable entries permissions - place binary or DLL to execute instead of legitimate
	for %%A in ("%path:;=";"%") do (
		accesschk.exe -accepteula -dvuqw %%k "%%~A" | findstr /v /l /i /c:"No matching objects found."
	)

	echo.
	echo.

	echo All users startup permissions - execute binary with permissions of logged user:
	accesschk.exe -accepteula -dvuqw %%k "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" | findstr /v /l /i /c:"No matching objects found."
	accesschk.exe -accepteula -vuqsw %%k "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" | findstr /v /l /i /c:"No matching objects found."

	echo.
	echo.

	echo Startup executables permissions - backdoor startup binaries and check if they are also run at startup by other users:
	accesschk.exe -accepteula -vuqsw %%k "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | findstr /v /l /i /c:"No matching objects found."
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			)
		)
	)
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			)
		)
	)
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			)
		)
	)
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					echo %%e | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%e | findstr /v /l /i /c:"No matching objects found.") || (
						cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%e" | findstr /v /l /i /c:"No matching objects found."
					)
				)
			)
		)
	)

	echo.
	echo.

	echo Startup executables directory permissions - try DLL injection:
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			)
		)
	)
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			)
		)
	)
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			)
		)
	)
	for /f "tokens=1,* delims='_'" %%a in ('reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce^|findstr /v /l /i /c:"HKEY_"') do (
		for /f "tokens=1,*" %%c in ('echo %%b') do (
			echo %%d | findstr /L /C:" -" 1>nul
			if errorlevel 1 (
				for /f "tokens=1 delims='/'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			) ELSE (
				for /f "tokens=1 delims='-'" %%e in ('echo %%d') do (
					set tpath=%%~dpe
					cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects found."
				)
			)
		)
	)

	echo.
	echo.

	echo Service binary permissions - backdoor service binary:
	for /f "tokens=2 delims='='" %%x in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do (
		for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
			for /f "tokens=*" %%y in ('cmd.exe /c accesschk.exe -accepteula -vuqsw %%k "%%z*"') do (
				echo %%y | findstr /v /l /i /c:"No matching objects found." >nul 2>&1 && (echo %%y)
			)
		)
	)

	echo.
	echo.

	echo Service directory permissions - try DLL injection:
	for /f "tokens=2 delims='='" %%x in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
		set tpath=%%~dpy
		for /f "tokens=*" %%z in ('cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!"') do (
			echo %%z | findstr /v /l /i /c:"No matching objects found." >nul 2>&1 && (echo %%z)
		)
	)

	echo.
	echo.

	echo Process binary permissions - backdoor process binary:
	for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
		for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
			for /f "tokens=*" %%y in ('cmd.exe /c accesschk.exe -accepteula -vuqsw %%k "%%z*"') do (
				echo %%y | findstr /v /l /i /c:"No matching objects found." >nul 2>&1 && (echo %%y)
			)
		)
	)

	echo.
	echo.

	echo Process directory permissions - try DLL injection:
	for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
		set tpath=%%~dpy
		for /f "tokens=*" %%z in ('cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!"') do (
			echo %%z | findstr /v /l /i /c:"No matching objects found." >nul 2>&1 && (echo %%z)
		)
	)

	echo.
	echo.

	echo Loaded DLLs permissions - backdoor DLL:
	for /f "tokens=2,*" %%a in ('Listdlls.exe -accepteula -u^|find /i "0x"^|find /i /v "system32"^|find /i /v "winsxs"') do (
		cmd.exe /c accesschk.exe -accepteula -vuqsw %%k "%%b*" | findstr /v /l /i /c:"No matching objects found."
	)

	echo.
	echo.

	echo Scheduled tasks binary permissions - backdoor scheduled task binary:
	for /f "delims=: tokens=1*" %%a in ('schtasks /query /fo LIST /V ^| findstr "\\" ^| findstr "\." ^| findstr /i /v /l /c:"c:\windows"') do (
		echo %%~b | findstr /L /C:" -" 1>nul
		if errorlevel 1 (
			for /f "tokens=1 delims='/'" %%c in ('echo %%~b') do (
				echo %%c | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%c | findstr /v /l /i /c:"No matching objects found.") || (
					cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%c" | findstr /v /l /i /c:"No matching objects found."
				)
			)
		) ELSE (
			for /f "tokens=1 delims='-'" %%c in ('echo %%~b') do (
				echo %%c | find """" >nul 2>&1 && (cmd.exe /c accesschk.exe -accepteula -vuqw %%k %%c | findstr /v /l /i /c:"No matching objects found.") || (
					cmd.exe /c accesschk.exe -accepteula -vuqw %%k "%%c" | findstr /v /l /i /c:"No matching objects found."
				)
			)
		)
	)

	echo.
	echo.

	echo Scheduled tasks directory permissions - try DLL injection:
	for /f "delims=: tokens=1*" %%a in ('schtasks /query /fo LIST /V ^| findstr "\\" ^| findstr "\." ^| findstr /i /v /l /c:"c:\windows"') do (
		echo %%~b | findstr /L /C:" -" 1>nul
		if errorlevel 1 (
			for /f "tokens=1 delims='/'" %%c in ('echo %%~b') do (
				set tpath=%%~dpc
				cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects 
			)
		) ELSE (
			for /f "tokens=1 delims='-'" %%c in ('echo %%~b') do (
				set tpath=%%~dpc
				cmd.exe /c accesschk.exe -accepteula -dvuqw %%k "!tpath:~,-1!" | findstr /v /l /i /c:"No matching objects
			)
		)
	)

	echo.
	echo.
)

goto :finish

:full
if "%mode%" NEQ "full" (goto :finish)

echo System Information (use windows-exploit-suggester.py to check for local exploits):
echo.
systeminfo 2>NUL
systeminfo > systeminfo_for_suggester.txt
echo.
echo ----------------------------------------------------------------------------
echo.
echo Environment variables:
echo.
set 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Information about current user:
echo.
net user %USERNAME% 2>NUL
net user %USERNAME% /domain 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Available drives:
echo.
wmic logicaldisk get deviceid,volumename,description | more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Network information:
echo.
ipconfig /all 2>NUL
echo.
route print 2>NUL
echo.
arp -A 2>NUL
echo.
netstat -ano 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Running processes:
echo.
tasklist /V 2>NUL
wmic process list | more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Scheduled processes:
echo.
schtasks /query /fo LIST /v 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Installed software:
echo.
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall 2>NUL
dir "%PROGRAMFILES%" 2>NUL
dir "%ProgramFiles(x86)%" 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Startup programs:
echo.
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" 2>NUL
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>NUL
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>NUL
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>NUL
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Temp files:
echo.
dir "%TEMP%" 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Startup services:
echo.
net start 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Installed drivers:
echo.
driverquery 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Applied hotfixes:
echo.
wmic qfe get Caption,Description,HotFixID,InstalledOn |more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Files that may contain Administrator password:
echo.
if exist %SystemDrive%\sysprep.inf echo %SystemDrive%\sysprep.inf 2>NUL
if exist %SystemDrive%\sysprep\sysprep.xml echo %SystemDrive%\sysprep\sysprep.xml 2>NUL
if exist %WINDIR%\system32\sysprep\Unattend.xml echo %WINDIR%\system32\sysprep\Unattend.xml 2>NUL
if exist %WINDIR%\system32\sysprep\Panther\Unattend.xml echo %WINDIR%\system32\sysprep\Panther\Unattend.xml 2>NUL
if exist "%WINDIR%\Panther\Unattend\Unattended.xml" echo "%WINDIR%\Panther\Unattend\Unattended.xml" 2>NUL
if exist "%WINDIR%\Panther\Unattended.xml" echo "%WINDIR%\Panther\Unattended.xml" 2>NUL
if exist "%WINDIR%\Panther\Unattend\Unattend.xml" echo "%WINDIR%\Panther\Unattend\Unattend.xml" 2>NUL
if exist "%WINDIR%\Panther\Unattend.xml" echo "%WINDIR%\Panther\Unattend.xml" 2>NUL
if exist %SystemDrive%\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT echo %SystemDrive%\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT 2>NUL
if exist %WINDIR%\panther\setupinfo echo %WINDIR%\panther\setupinfo 2>NUL
if exist %WINDIR%\panther\setupinfo.bak echo %WINDIR%\panther\setupinfo.bak 2>NUL
if exist %SystemDrive%\unattend.xml echo %SystemDrive%\unattend.xml 2>NUL
if exist %WINDIR%\system32\sysprep.inf echo %WINDIR%\system32\sysprep.inf 2>NUL
if exist %WINDIR%\system32\sysprep\sysprep.xml echo %WINDIR%\system32\sysprep\sysprep.xml 2>NUL
if exist %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config echo %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>NUL
if exist %SystemDrive%\inetpub\wwwroot\web.config echo %SystemDrive%\inetpub\wwwroot\web.config 2>NUL
if exist "%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml" echo "%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml" 2>NUL
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password 2>NUL
reg query HKCU\Software\SimonTatham\PuTTY\Sessions 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking AlwaysInstallElevated (install *.msi files as NT AUTHORITY\SYSTEM - exploit/windows/local/always_install_elevated):
echo.
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>NUL
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking permissions on services (changing BINARY_PATH_NAME - possible if SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL):
echo It is also adviced to use Instrsrv.exe and Srvany.exe to try to create user defined service
echo.
for /f "tokens=2" %%x in ('sc query state^= all^|find /i "service_name"') do accesschk.exe -accepteula -ucqv %%x
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking permissions on services registy keys and subkeys (changing ImagePath value of a service):
accesschk.exe -accepteula -kvuqsw hklm\System\CurrentControlSet\services
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking permissions on uninstall registy keys and subkeys (changing binary paths):
accesschk.exe -accepteula -kvuqsw HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking BINARY_PATH_NAME for all services (if there is a space and path is not enclosed with quotes then it may be vulnerable - exploit/windows/local/trusted_service_path):
echo.
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME') do echo %%~s
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading:
if exist C:\Windows\CCM\SCClient.exe (
    echo Installed.
) else (
    echo Not Installed.
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking file permissions of running services (File backdooring - exploit/windows/local/service_permissions):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		cmd.exe /c icacls "%%z" ^| more
	)
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking directory permissions of running services (DLL injection):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	set tpath=%%~dpy
	cmd.exe /c icacls "!tpath:~,-1!" ^| more
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		cmd.exe /c icacls "%%z" ^| more
	)
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking directory permissions of running processes (DLL injection):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	set tpath=%%~dpy
	cmd.exe /c icacls "!tpath:~,-1!" ^| more
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking named pipes permissions (it depends on what named pipe does with written data):
echo.
for /f "tokens=1" %%x in ('pipelist.exe -accepteula') do (
	accesschk.exe -accepteula \pipe\%%x
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo List unsigned DLLs loaded by processes and their privileges (good to check also "not found" DLLs and registry keys using Procmon.exe):
echo.
for /f "tokens=2,*" %%a in ('Listdlls.exe -accepteula -u^|find /i "0x"^|find /i /v "system32"^|find /i /v "winsxs"') do (
	cmd.exe /c icacls "%%b" ^| more
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo PATH variable entries permissions - place binary or DLL to execute instead of legitimate
for %%A in ("%path:;=";"%") do (
	cmd.exe /c icacls "%%~A" ^| more
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking system32 permissions misconfiguration (binaries that are good to backdoor - system32sethc.exe (Sticky Keys), system32utilman.exe):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
cmd.exe /c icacls "C:\Windows\system32" ^| more
echo.
echo ----------------------------------------------------------------------------
echo.
echo ProgramData permissions - backdoor windows binaries:
accesschk.exe -accepteula -dvuqw %%k "C:\ProgramData" | findstr /v /l /i /c:"No matching objects found."
accesschk.exe -accepteula -vuqsw %%k "C:\ProgramData" | findstr /v /l /i /c:"No matching objects found."
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking Windows Temp read permissions misconfiguration (trying DLL Sideloading in each created directory):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
cmd.exe /c icacls "C:\Windows\Temp" ^| more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking Program Files permissions misconfiguration - backdoor windows binaries:
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
accesschk.exe -accepteula -dvuqw %%k "%ProgramFiles%" | findstr /v /l /i /c:"No matching objects found."
accesschk.exe -accepteula -vuqsw %%k "%ProgramFiles%" | findstr /v /l /i /c:"No matching objects found."
accesschk.exe -accepteula -dvuqw %%k "%ProgramFiles(x86)%" | findstr /v /l /i /c:"No matching objects found."
accesschk.exe -accepteula -vuqsw %%k "%ProgramFiles(x86)%" | findstr /v /l /i /c:"No matching objects found."
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking startup directory permissions for all users (executing binaries with permissions of logged user):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
cmd.exe /c icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" ^| more

for %%k in (%*) do (
	echo.
	echo ----------------------------------------------------------------------------
	echo Checking possibly weak permissions for %%k group:
	echo.
	echo Checking writable HKLM registry keys - eg. changing paths:
	accesschk.exe -accepteula -kvuqsw %%k hklm

	if "%long%" == "yes" (
		echo ----------------------------------------------------------------------------
		echo.
		echo Weak file/directory permissions on all drives:
		echo.
		for /f %%x in ('wmic logicaldisk get name^| more') do (
			set tdrive=%%x
			if "!tdrive:~1,2!" == ":" (
				accesschk.exe -accepteula -uwdqs %%k %%x
				accesschk.exe -accepteula -uwqs %%k %%x\*.*
			)
		)
		echo.
	)
)

if "%long%" == "yes" (
	echo ----------------------------------------------------------------------------
	echo.
	echo Looking for sensitive registry keys:
	echo.
	reg query HKLM /f pass /t REG_SZ /s
	reg query HKCU /f pass /t REG_SZ /s
	reg query HKLM /f pwd /t REG_SZ /s
	reg query HKCU /f pwd /t REG_SZ /s
	echo.
	echo ----------------------------------------------------------------------------
	echo.
	echo Looking for sensitive files:
	echo.
	for /f %%x in ('wmic logicaldisk get name^| more') do (
		set tdrive=%%x
		if "!tdrive:~1,2!" == ":" (
			%%x
			findstr /si pass *.xml *.ini *.txt *.cfg *.config
			findstr /si pwd *.xml *.ini *.txt *.cfg *.config
		)
	)
	echo.
)

:finish
