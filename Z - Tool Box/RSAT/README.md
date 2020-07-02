# ADModule
Microsoft signed DLL for the ActiveDirectory PowerShell module

Just a backup for the Microsoft's ActiveDirectory PowerShell module from Server 2016 with RSAT and module installed. The DLL is usually found at this path: C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management

and the rest of the module files at this path:
C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory\

## Usage
You can copy this DLL to your machine and use it to enumerate Active Directory without installing RSAT and without having administrative privileges. 

PS C:\> Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
![Alt text](/img/AD_Module.png?raw=true "ADModule")

To be able to list all the cmdlets in the module, import the module as well. Remember to import the DLL first. 

PS C:\> Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose

PS C:\> Import-Module C:\AD\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1

PS C:\> Get-Command -Module ActiveDirectory

## Benefits
There are many benefits like very low chances of detection by AV, very wide coverage by cmdlets, good filters for cmdlets, signed by Microsoft etc. The most useful one, however, is that this module works flawlessly from PowerShell's Constrained Language Mode
![Alt text](/img/AD_Module_CLM.png?raw=true "ADModule in CLM")



## Blog 
https://www.labofapenetrationtester.com/2018/10/domain-enumeration-from-PowerShell-CLM.html
