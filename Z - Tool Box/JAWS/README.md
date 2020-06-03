# JAWS - Just Another Windows (Enum) Script

JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7.

## Usage:


**Run from within CMD shell and write out to file.**
```
CMD C:\temp> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
```
**Run from within CMD shell and write out to screen.**
```
CMD C:\temp> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1
```
**Run from within PS Shell and write out to file.**
```
PS C:\temp> .\jaws-enum.ps1 -OutputFileName Jaws-Enum.txt
```

## Current Features
  - Network Information (interfaces, arp, netstat)
  - Firewall Status and Rules
  - Running Processes
  - Files and Folders with Full Control or Modify Access
  - Mapped Drives
  - Potentially Interesting Files
  - Unquoted Service Paths
  - Recent Documents
  - System Install Files 
  - AlwaysInstallElevated Registry Key Check
  - Stored Credentials
  - Installed Applications
  - Potentially Vulnerable Services
  - MuiCache Files
  - Scheduled Tasks

## Known Issues

- Output for firewall rules can sometimes be clipped.
- When running from within a shell the script doesnt always tell you its finished.
- When running within some PowerShell reverse shells the running menu isnt shown. 



## To Do
  - Add full directory listing with user defined depth
  - Read SAM file permissions
  - Improve output
