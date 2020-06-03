<#
.SYNOPSIS
Windows enumeration script
.DESCRIPTION
This script is designed to be used in a penetration test or CTF
enviroment. It will enumerate useful information from the host
for privilege escalation.
.EXAMPLE
PS > .\jaws-enum.ps1 
will write results out to screen.
.EXAMPLE
PS > .\jaws-enum.ps1 -OutputFileName Jaws-Enum.txt
Writes out results to Jaws-Enum.txt in current directory.
.LINK
https://github.com/411Hall/JAWS
#>
Param(
    [String]$OutputFilename = ""
)

function JAWS-ENUM {
    write-output "`nRunning J.A.W.S. Enumeration"
    $output = "" 
    $output = $output +  "############################################################`r`n"
    $output = $output +  "##     J.A.W.S. (Just Another Windows Enum Script)        ##`r`n"
    $output = $output +  "##                                                        ##`r`n"
    $output = $output +  "##           https://github.com/411Hall/JAWS              ##`r`n"
    $output = $output +  "##                                                        ##`r`n"
    $output = $output +  "############################################################`r`n"
    $output = $output +  "`r`n"
    $win_version = (Get-WmiObject -class Win32_OperatingSystem)
    $output = $output +  "Windows Version: " + (($win_version.caption -join $win_version.version) + "`r`n")
    $output = $output +  "Architecture: " + (($env:processor_architecture) + "`r`n")
    $output = $output +  "Hostname: " + (($env:ComputerName) + "`r`n")
    $output = $output +  "Current User: " + (($env:username) + "`r`n")
    $output = $output +  "Current Time\Date: " + (get-date)
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    write-output "	- Gathering User Information"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Users`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
        $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        $output = $output +  "----------`r`n"
        $output = $output +  "Username: " + $_.Name +  "`r`n"
        $output = $output +  "Groups:   "  + $groups +  "`r`n"
    }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Network Information`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (ipconfig | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Arp`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (arp -a | out-string) 
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " NetStat`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (netstat -ano | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Firewall Status`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  "`r`n"
    $Firewall = New-Object -com HNetCfg.FwMgr
    $FireProfile = $Firewall.LocalPolicy.CurrentProfile  
    if ($FireProfile.FirewallEnabled -eq $False) {
        $output = $output +  ("Firewall is Disabled" + "`r`n")
        } else {
        $output = $output +  ("Firwall is Enabled" + "`r`n")
        }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " FireWall Rules`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    Function Get-FireWallRule
    {Param ($Name, $Direction, $Enabled, $Protocol, $profile, $action, $grouping)
    $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
    If ($name)      {$rules= $rules | where-object {$_.name     -like $name}}
    If ($direction) {$rules= $rules | where-object {$_.direction  -eq $direction}}
    If ($Enabled)   {$rules= $rules | where-object {$_.Enabled    -eq $Enabled}}
    If ($protocol)  {$rules= $rules | where-object {$_.protocol   -eq $protocol}}
    If ($profile)   {$rules= $rules | where-object {$_.Profiles -bAND $profile}}
    If ($Action)    {$rules= $rules | where-object {$_.Action     -eq $Action}}
    If ($Grouping)  {$rules= $rules | where-object {$_.Grouping -like $Grouping}}
    $rules}
    $output = $output +  (Get-firewallRule -enabled $true | sort direction,applicationName,name | format-table -property Name , localPorts,applicationname | out-string)
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Hosts File Content`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  "`r`n"
    $output = $output + ((get-content $env:windir\System32\drivers\etc\hosts | out-string) + "`r`n")
    $output = $output +  "`r`n"
    write-output "	- Gathering Processes, Services and Scheduled Tasks"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Processes`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  ((Get-WmiObject win32_process | Select-Object Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | sort name | format-table -wrap -autosize | out-string) + "`r`n")
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Scheduled Tasks`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  "Current System Time: " + (get-date)
    $output = $output + (schtasks /query /FO CSV /v | convertfrom-csv | where { $_.TaskName -ne "TaskName" } | select "TaskName","Run As User", "Task to Run"  | fl | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Services`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (get-service | Select Name,DisplayName,Status | sort status | Format-Table -Property * -AutoSize | Out-String -Width 4096)
    $output = $output +  "`r`n"
    write-output "	- Gathering Installed Software"
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Installed Programs`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Installed Patches`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (Get-Wmiobject -class Win32_QuickFixEngineering -namespace "root\cimv2" | select HotFixID, InstalledOn| ft -autosize | out-string )
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Program Folders`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + "`n`rC:\Program Files`r`n"
    $output = $output +  "-------------"
    $output = $output + (get-childitem "C:\Program Files"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string)
    $output = $output + "C:\Program Files (x86)`r`n"
    $output = $output +  "-------------------"
    $output = $output + (get-childitem "C:\Program Files (x86)"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string)
    $output = $output +  "`r`n"
    write-output "	- Gathering File System Information"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Files with Full Control and Modify Access`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $files = get-childitem C:\
    foreach ($file in $files){
        try {
            $output = $output +  (get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf,*.ini -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
            where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | 
            ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
            }
        catch {
            $output = $output +   "`nFailed to read more files`r`n"
        }
        }

    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Folders with Full Control and Modify Access`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $folders = get-childitem C:\
    foreach ($folder in $folders){
        try {
            $output = $output +  (Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue | ?{ $_.PSIsContainer} | get-acl  | select path -expand access |  
            where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|CREATOR OWNER|NT SERVICE"}  | where {$_.filesystemrights -match "FullControl|Modify"} | 
            select path,filesystemrights,IdentityReference |  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
             }
        catch {
            $output = $output +  "`nFailed to read more folders`r`n"
        }
        }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Mapped Drives`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (Get-WmiObject -Class Win32_LogicalDisk | select DeviceID, VolumeName | ft -hidetableheaders -autosize | out-string -Width 4096)
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Unquoted Service Paths`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (cmd /c  'wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """')
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Recent Documents`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent"  -EA SilentlyContinue | select Name | ft -hidetableheaders | out-string )
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Potentially Interesting Files in Users Directory `r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " 10 Last Modified Files in C:\User`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (Get-ChildItem 'C:\Users' -recurse -EA SilentlyContinue | Sort {$_.LastWriteTime} |  %{$_.FullName } | select -last 10 | ft -hidetableheaders | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " MUICache Files`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    get-childitem "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\" -EA SilentlyContinue |
    foreach { $CurrentKey = (Get-ItemProperty -Path $_.PsPath)
       if ($CurrentKey -match "C:\\") {
          $output = $output + ($_.Property -join "`r`n")
       }
    }
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    write-output "	- Looking for Simple Priv Esc Methods"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " System Files with Passwords`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $files = ("unattended.xml", "sysprep.xml", "autounattended.xml","unattended.inf", "sysprep.inf", "autounattended.inf","unattended.txt", "sysprep.txt", "autounattended.txt")
    $output = $output +  (get-childitem C:\ -recurse -include $files -EA SilentlyContinue  | Select-String -pattern "<Value>" | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " AlwaysInstalledElevated Registry Key`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $HKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $HKCU =  "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (($HKLM | test-path) -eq "True") 
    {
        if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
        {
            $output = $output +   "AlwaysInstallElevated enabled on this host!"
        }
    }
    if (($HKCU | test-path) -eq "True") 
    {
        if (((Get-ItemProperty -Path $HKCU -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
        {
            $output = $output +   "AlwaysInstallElevated enabled on this host!"
        }
    }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Stored Credentials`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (cmdkey /list | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Checking for AutoAdminLogon `r`n"
    $output = $output + "-----------------------------------------------------------`r`n"
    $Winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (get-itemproperty -path $Winlogon -Name AutoAdminLogon -ErrorAction SilentlyContinue) 
        {
        if ((get-itemproperty -path $Winlogon -Name AutoAdminLogon).AutoAdminLogon -eq 1) 
            {
            $Username = (get-itemproperty -path $Winlogon -Name DefaultUserName).DefaultUsername
            $output = $output + "The default username is $Username `r`n"
            $Password = (get-itemproperty -path $Winlogon -Name DefaultPassword).DefaultPassword
            $output = $output + "The default password is $Password `r`n"
            $DefaultDomainName = (get-itemproperty -path $Winlogon -Name DefaultDomainName).DefaultDomainName
            $output = $output + "The default domainname is $DefaultDomainName `r`n"
            }
        }
    $output = $output +  "`r`n"
    if ($OutputFilename.length -gt 0)
       {
        $output | Out-File -FilePath $OutputFileName -encoding utf8
        }
    else
        {
        clear-host
        write-output $output
        }
}

if ($OutputFilename.length -gt 0)
    {
        Try 
            { 
                [io.file]::OpenWrite($OutputFilename).close()  
                JAWS-ENUM
            }
        Catch 
            { 
                Write-Warning "`nUnable to write to output file $OutputFilename, Check path and permissions" 
            }
    } 
else 
    {
    JAWS-ENUM
    }
