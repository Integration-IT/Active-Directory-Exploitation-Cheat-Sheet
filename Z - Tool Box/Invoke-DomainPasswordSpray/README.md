# DomainPasswordSpray
DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!

## Quick Start Guide
Open a PowerShell terminal from the Windows command line with 'powershell.exe -exec bypass'.

Type 'Import-Module DomainPasswordSpray.ps1'.

The only option necessary to perform a password spray is either -Password for a single password or -PasswordList to attempt multiple sprays. When using the -PasswordList option Invoke-DomainPasswordSpray will attempt to gather the account lockout observation window from the domain and limit sprays to one per observation window to avoid locking out accounts.

The following command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Spring2017.
```PowerShell
Invoke-DomainPasswordSpray -Password Spring2017
```

The following command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to one attempt during each window. The results of the spray will be output to a file called sprayed-creds.txt
```PowerShell
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
```

### Invoke-DomainPasswordSpray Options
```
UserList          - Optional UserList parameter. This will be generated automatically if not specified.
Password          - A single password that will be used to perform the password spray.
PasswordList      - A list of passwords one per line to use for the password spray (Be very careful not to lockout accounts).
OutFile           - A file to output the results to.
Domain            - A domain to spray against.
Force             - Forces the spray to continue without prompting for confirmation.

```
## Get-DomainUserList Module
The function Get-DomainUserList allows you to generate a userlist from the domain. It has options to remove disabled accounts and those that are about to be locked out. This is performed automatically in DomainPasswordSpray if no user list is specified. 

This command will write the domain user list without disabled accounts or accounts about to be locked out to a file at "userlist.txt".
```PowerShell
Get-DomainUserList -Domain domainname -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt
```
