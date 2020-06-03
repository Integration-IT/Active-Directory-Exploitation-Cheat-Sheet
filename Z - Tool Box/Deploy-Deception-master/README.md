# Deploy-Deception

### Deploy-Deception is a PowerShell module to deploy active directory decoy objects.
By [nikhil_mitt](https://twitter.com/nikhil_mitt)

### Usage

Import the module in the current PowerShell session.

PS C:\\> Import-Module C:\Deploy-Deception\Deploy-Deception.psd1

Use the script with dot sourcing.

PS C:\\> . C:\Deploy-Deception\Deploy-Deception.ps1

To get help about any function, use:

PS C:\\> Get-Help [functionname] -Full

For example, to see the help about Deploy-UserDeception, use

PS C:\\> Get-Help Deploy-UserDeception -Full

### Functions
Deploy-Deception currently has following functions:

All the functions must be run on a DC with domain admin privileges. There are multiple attributes and flags
which can be set while deploying a decoy. These attributes and flags make the decoy interesting for an attacker. 
When a right, say, ReadProperty is used to access the decoy, a Security Event 4662 is logged. 

Note that Windows Settings|Security Settings|Advanced Audit Policy Configuration|DS Access|Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging. 

### Deploy-UserDeception
This function sets up auditing when a specified Right is used by a specifed principal against the decoy user object.

EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -Verbose

Creates a decoy user whose password never expires and a 4662 is logged whenever ANY property of the user is read. Very verbose!

EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose

Creates a decoy user whose password never expires and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property of the user is read.

This property is not read by net.exe, WMI classes (like Win32_UserAccount) and ActiveDirectory module.

But LDAP based tools like PowerView and ADExplorer trigger the logging.

EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName user -UserLastName manager-control -Password Pass@123 | Deploy-UserDeception -UserFlag AllowReversiblePasswordEncryption -Right ReadControl -Verbose 

Creates a decoy user which has Allow Reverisble Password Encrpytion property set. 

A 4662 is logged whenever DACL of the user is read.

This property is not read by enumeration tools unless specifically DACL or all properties for the decoy user are force read.

### Deploy-SlaveDeception
This function sets up auditing when a specified Right is used over the slave user by a master user who has FUllControl/GenericALl over the slave user.

EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName master -UserLastName user -Password Pass@123 

PS C:\\> Create-DecoyUser -UserFirstName slave -UserLastName user -Password Pass@123 | Deploy-SlaveDeception -DecoySamAccountName masteruser -Verbose

The first command creates a deocy user 'masteruser'.

The second command creates a decoy user 'slaveuser' and provides masteruser GenericAll rights over slaveuser.

For both the users a 4662 is logged whenever there is any interaction with them.

EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName master -UserLastName user -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose

PS C:\\> Create-DecoyUser -UserFirstName slave -UserLastName user -Password Pass@123 | Deploy-SlaveDeception -DecoySamAccountName masteruser -Verbose

PS C:\\> Deploy-SlaveDeception -SlaveSamAccountName slaveuser -DecoySamAccountName masteruser -Verbose 

The first command creates a decoy user 'masteruser' whose password never expires and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property of the user is read.

The second command creates a decoy user 'slaveuser' whose password never expires and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property of the user is read.

The third command grants masteruser GenericAll rights over slaveuser.

The above three commands make masteruser and slaveuser attractive for an attacker and the logging is triggered only for aggressive enumeration.

EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName master -UserLastName user -Password Pass@123

PS C:\\> Create-DecoyUser -UserFirstName slave -UserLastName user -Password Pass@123 

PS C:\\> Deploy-SlaveDeception -SlaveSamAccountName slaveuser -DecoySamAccountName masteruser -Verbose 

PS C:\\> Deploy-UserDeception -DecoySamAccountName slaveuser -Principal masteruser -Right WriteDacl -Verbose

The first three commands create a slaveuser, create a master user and provide masteruser GenericAll rights on slaveuser.

The foruth command triggers a 4662 log only when masteruser is used change DACL (WirteDacl) of the slaveuser. 

This is useful when targeting lateral movement and it is assumed that an adversary will get access to masteruser.
For example, masteruser could be a honeyuser whose credentials are left on multipe machines or masteruser can have its
usable password in Description.

### Deploy-PrivilegedUserDeception
This function deploys a decoy user which has high privileges like membership of the Domain Admins group. 
EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName dec -UserLastName da -Password Pass@123 | Deploy-PrivilegedUserDeception -Technique DomainAdminsMemebership -Protection DenyLogon -Verbose

Create a decoy user named decda and make it a member of the Domain Admins group. As a protection against potential abuse,
Deny logon to the user on any machine. Please be aware that if another DA gets comprimised the DenyLogon setting can be removed.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

EXAMPLE

PS C:\\> Deploy-PrivilegedUserDeception -DecoySamaccountName decda -Technique DomainAdminsMemebership -Protection LogonWorkStation nonexistent -Verbose

Use existing user decda and make it a member of the Domain Admins group. As a protection against potential abuse,
set LogonWorkstation for the user to a nonexistent machine.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

EXAMPLE

PS C:\\> Deploy-PrivilegedUserDeception -DecoySamaccountName decda -Technique DCSyncRights -Protection LogonWorkStation nonexistent -Verbose

Use existing user decda and make provide it DCSyncRights. As a protection against potential abuse, set LogonWorkstation for the user to a nonexistent machine.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

EXAMPLE

PS C:\\> Create-DecoyUser -UserFirstName test -UserLastName da -Password Pass@123 | Deploy-PrivilegedUserDeception -Technique DomainAdminsMemebership -Protection LogonWorkStation -LogonWorkStation revert-dc -CreateLogon -Verbose 

Create a decoy user named decda and make it a member of the Domain Admins group. 
As a protection against potential abuse, set LogonWorkstation for the user to the DC where this function is executed. 

To avoid detection of the decoy which relies on logoncount use the CreateLogon option which starts and stops a process as the
decoy user on the DC. A user profile is created on the DC when this parameter is used. 

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

### Deploy-ComputerDeception
This function sets up auditing when a specified Right is used by a specifed principal against the decoy computer object.

PS C:\\> Create-DecoyComputer -ComputerName revert-web -Verbose | Deploy-ComputerDeception -PropertyFlag TrustedForDelegation -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a  -Verbose

Creates a decoy computer that has Unconstrained Delegation enabled and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property or all the properties
of the computer are read.

EXAMPLE

PS C:\\> Deploy-ComputerDeception -DecoyComputerName comp1 -PropertyFlag TrustedForDelegation -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a  -Verbose

Uses an existing computer object and set Unconstrained Delegation on it. A 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property or all the properties
of the computer are read.

Using a real machine for the decoy is always recommended as it is harder to identify as a decoy. 


EXAMPLE

PS C:\\> Deploy-ComputerDeception -DecoyComputerName comp1 -OperatingSystem "Windows Server 2003" -Right ReadControl -Verbose
Uses an existing computer object and set its Operating System property to Windows Server 2003. 

A 4662 is logged whenever DACL or all the properties of the computer are read.

Using a real machine for the decoy is always recommended as it is harder to identify as a decoy. 

### Deploy-GroupDeception
This function sets up auditing when a specified Right is used by a specifed principal against the decoy group object.

EXAMPLE

PS C:\\> Create-DecoyGroup -GroupName 'Forest Admins' -Verbose | Deploy-GroupDeception -AddMembers slaveuser -AddToGroup dnsadmins -Right ReadControl -Verbose 

Creates a decoy Group 'Forest Admins', adds slaveuser as a member and makes the group part of the dnsadmins group. 
A 4662 is logged whenever DACL or all the properties of the group are read.

EXAMPLE

PS C:\\> Create-DecoyGroup -GroupName "Forest Admins" -Verbose | Deploy-GroupDeception -AddMembers -Members slaveuser -AddToGroup -AddToGroupName dnsadmins -GUID bc0ac240-79a9-11d0-9020-00c04fc2d4cf -Verbose

Creates a decoy Group 'Forest Admins',adds slaveuser as a member and makes the group part of the dnsadmins group.
A 4662 is logged whenever membership of the Forest Admins group is listed. 

### Bugs, Feedback and Feature Requests
Please raise an issue if you encounter a bug or have a feature request. 

### Contributing
You can contribute by fixing bugs or contributing to the code. If you cannot code, you can test the deployment in your network and share the results about false positives with me to help improve the project.

### Blog Posts
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html

