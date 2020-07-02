#Requires –Modules ActiveDirectory

<#

File: Deploy-Deception.ps1
Author: Nikhil Mittal (@nikhil_mitt)
Description: A PowerShell module to deploy active directory decoy objects.
Required Dependencies: ActiveDirectory Module by Microsoft

#>


##################################### Helper Functions #####################################

function Create-DecoyUser
{
<#
.SYNOPSIS
Create a user object.
 
.DESCRIPTION
Creates a user object on the domain. Must be run on a DC with domain admin privileges.

.PARAMETER UserFirstName
First name of the user to be crated. 

.PARAMETER UserLastName
Last name of the user to be crated. 

.PARAMETER Password
Password for the user to be created. 

.PARAMETER OUDistinguishedName
DistinguishedName of OU where the user will be created. The default User OU is used if this paramter is not specified.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123
Use the above command to create a user 'usermanager'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $UserFirstName,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $UserLastName,
        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $Password,
        
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $OUDistinguishedName
    )

        $UserDisplayName = $UserFirstName + $UserLastName
        Write-Verbose "Creating user $UserDisplayName."

        if (!$OUDistinguishedName)
        {
            Write-Verbose "Creating user $UserDisplayName."
            (New-ADUser -Name $UserDisplayName -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -SamAccountName $UserDisplayName -Enabled $True -DisplayName $UserDisplayName -PassThru).SamAccountName
        }
        else
        {
            Write-Verbose "Creating user $UserDisplayName in $OUDistinguishedName."
            (New-ADUser -Name $UserDisplayName -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -SamAccountName $UserDisplayName -Enabled $True -DisplayName $UserDisplayName -Path $OUDistinguishedName -PassThru).SamAccountName
        }

}

function Create-DecoyComputer
{
<#
.SYNOPSIS
Create a computer object.
 
.DESCRIPTION
Creates a computer object on the domain. Must be run on a DC with domain admin privileges.

.PARAMETER ComputerName
Name of the computer to be crated. 

.PARAMETER OUDistinguishedName
DistinguishedName of OU where the computer will be created. The default Computer OU is used if this paramter is not specified.

.EXAMPLE
PS C:\> Create-DecoyComputer -ComputerName revert-web -Verbose
Use the above command to create a computer 'revert-web'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $ComputerName,
             
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $OUDistinguishedName
    )
        $DNSHostname = $ComputerName + "." + (Get-ADDomain).DNSRoot
        Write-Verbose "Creating computer $ComputerName."

        if (!$OUDistinguishedName)
        {
            Write-Verbose "Creating computer $DNSHostname."
            (New-ADComputer -Name $ComputerName -Enabled $True -DNSHostName $DNSHostname -PassThru).SamAccountName
        }
        else
        {
            Write-Verbose "Creating computer $DNSHostname in $OUDistinguishedName."
            (New-ADComputer -Name $ComputerName -Enabled $True -DNSHostName $DNSHostname -Path $OUDistinguishedName -PassThru).SamAccountName
        }

}

function Create-DecoyGroup
{
<#
.SYNOPSIS
Create a Group object.
 
.DESCRIPTION
Creates a Group object on the domain. Must be run on a DC with domain admin privileges.

.PARAMETER GroupName
Name of the Group to be crated. 

.PARAMETER GroupScope
The scope of created group. Default is Global.

.EXAMPLE
PS C:\> Create-DecoyGroup -GroupName 'Forest Admins' -Verbose
Use the above command to create a Global Group 'Forest Admins'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $GroupName,
             
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        [ValidateSet ("DomainLocal","Global","Universal")]
        $GroupScope = "Global"
    )
        Write-Verbose "Creating Group $GroupName."
        (New-ADGroup -Name $GroupName -GroupScope $GroupScope -PassThru).SamAccountName

}

function Get-ADObjectDetails
{
<#
.SYNOPSIS
Helper function to retrieve details about an object from domain.
 
.DESCRIPTION
Helper function to retrieve details - SamAccountName, Distibguished Name and ACL for an object from domain.

.PARAMETER UserName
Username to get details for. 

.PARAMETER SamAccountName
SamAccountName of a user to get details for.

.PARAMETER DistinguisedName
DistinguishedName of a user to get details for. 

.PARAMETER ComputerName
ComputerName to get details for. 

.PARAMETER GroupName
GroupName to get details for. 

.PARAMETER OUName
OUName to get details for.

.EXAMPLE
PS C:\> Get-ADObjectDetails -SamAccountName usermanager.
Use the above command to get details for the user 'usermanager'.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 

    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $UserName,
        
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $SAMAccountName,
        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $DistinguishedName,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $ComputerName,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $GroupName,
        
        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $OUName
    )

    if ($UserName)
    {
        $objDN = (Get-ADUser -Filter {Name -eq $UserName}).distinguishedname
        $TargetSamAccountName = (Get-ADUser -Filter {Name -eq $UserName}).SamAccountName
    }
    elseif ($SAMAccountName)
    {
        $objDN = (Get-ADUser -Identity $SamAccountName).distinguishedname
        $TargetSamAccountName = $SAMAccountName
    }
    elseif ($DistinguishedName)
    {
        $objDN = $DistinguishedName
        $TargetSamAccountName = (Get-ADUser -Filter {Name -eq $UserName}).SamAccountName
    }
    elseif ($ComputerName)
    {
        $objDN = (Get-ADComputer -Identity $ComputerName).distinguishedname
        $TargetSamAccountName = (Get-ADComputer -Identity $ComputerName).SamAccountName
    }
    elseif ($GroupName)
    {
        $objDN = (Get-ADGroup -Identity $GroupName).distinguishedname
        $TargetSamAccountName = (Get-ADGroup -Identity $GroupName).SamAccountName
    }

    elseif ($OUName)
    {
        $objDN = (Get-ADOrganizationalUnit -Filter {Name -eq $OUName}).distinguishedname
        $TargetSamAccountName = (Get-ADOrganizationalUnit -Filter {Name -eq $OUName}).SamAccountName
    }
    else
    {
        Write-Output 'Cannot find the object.'
    }
    #Write-Verbose "Getting the existing ACL for $objDN."
    $ACL = Get-Acl -Path "AD:\$objDN"

    
    # A PSObject for returning properties

    $ObjectProperties = @{

        SamAccountName = $TargetSamAccountName
        DistinguishedName = $objDN
        ACL = $ACL

    }

    New-Object psobject -Property $ObjectProperties
}

function Set-AuditRUle
{
<#
.SYNOPSIS
Helper function to set auditing for an object in domain.
 
.DESCRIPTION
Helper function to set auditing for an object in domain.

.PARAMETER UserName
Username to set SACL for. 

.PARAMETER SamAccountName
SamAccountName of a user to set SACL for.

.PARAMETER DistinguisedName
DistinguishedName of a user to set SACL for. 

.PARAMETER ComputerName
ComputerName to set SACL for. 

.PARAMETER GroupName
GroupName to set SACL for. 

.PARAMETER OUName
OUName to set SACL for.

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadProperty right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#> 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $UserName,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $SAMAccountName,
        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $DistinguishedName,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $ComputerName,
        
        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $GroupName,

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $OUName,

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        $Principal,

        [Parameter(Position = 7, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadProperty",

        [Parameter(Position = 8, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 9, Mandatory = $False)]
        [String]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing
    )
    
    $objectdetails = Get-ADObjectDetails -SAMAccountName $SamAccountName -ComputerName $ComputerName -GroupName $GroupName -OUName $OUName

    $ACL = $objectdetails.ACL

    $sid = New-Object System.Security.Principal.NTAccount($Principal)
    if (!$GUID)
    {
        $AuditRule = New-Object DirectoryServices.ActiveDirectoryAuditRule($sid,$Right,$AuditFlag)
    }

    # Set Auditing for a specific property in the object with the property or attribute GUID
    # Interesting GUID
    # userAccountControl - bf967a68-0de6-11d0-a285-00aa003049e2
    # x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a
    elseif ($GUID)
    {
        $objectGuid = New-Object Guid $GUID
        $AuditRule = New-Object DirectoryServices.ActiveDirectoryAuditRule($sid,$Right,$AuditFlag,$objectGuid)
    }
    else
    {
        Write-Warning "Please specify a right. If you are targeting a specific object type, please provide a GUID."
    }

    $objDN = $objectdetails.DistinguishedName

    if(!$RemoveAuditing)
    {
        Write-Verbose "Turning ""$AuditFlag"" Auditing on for ""$objDN"" when ""$Principal"" uses ""$Right"" right."
        $ACL.AddAuditRule($AuditRule)
    }
    else
    {
        Write-Verbose "Removing ""$AuditFlag"" Auditing for ""$objDN"" when ""$Principal"" uses ""$Right"" right."
        $ACL.RemoveAuditRule($AuditRule)
    }

    Set-Acl "AD:\$objDN" -AclObject $ACL

}

################################## End of Helper Functions #################################


function Deploy-UserDeception
{
<#
.SYNOPSIS
Deploys the specific decoy user to log Security Event 4662 when a specific Right is used against it.

.DESCRIPTION
This function sets up auditing when a specified Right is used by a specifed principal against the decoy user object.

The function must be run on a DC with domain admin privileges. There are multiple user attributes and flags
which can be set while deploying the decoy. These attributes and flags make the decoy interesting for an attacker. 
When a right, say, ReadProperty is used to access the decoy user, a Security Event 4662 is logged. 

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging. 

.PARAMETER DecoySamAccountName
SamAccountName of the decoy user.  

.PARAMETER DecoyDistinguishedName
DistinguishedName of the decoy user. 

.PARAMETER UserFlag
A decoy user property which would be 'interesting' for an attacker.

.PARAMETER PasswordInDescription
Leave a password in Description of the decoy user.

.PARAMETER SPN
Set 'interesting' SPN for the decoy user in the format servicename/host

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadProperty right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -Verbose
Creates a decoy user whose password never expires and a 4662 is logged whenever ANY property of the user is read. Very verbose!

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose
Creates a decoy user whose password never expires and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property of the user is read.

This property is not read by net.exe, WMI classes (like Win32_UserAccount) and ActiveDirectory module.
But LDAP based tools like PowerView and ADExplorer trigger the logging.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName user -UserLastName manager-control -Password Pass@123 | Deploy-UserDeception -UserFlag AllowReversiblePasswordEncryption -Right ReadControl -Verbose 
Creates a decoy user which has Allow Reverisble Password Encrpytion property set. 
A 4662 is logged whenever DACL of the user is read.

This property is not read by enumeration tools unless specifically DACL or all properties for the decoy user are force read.

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
    [CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="SamAccountName",Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $DecoySamAccountName,
        
        [Parameter(ParameterSetName="ADSPath",Position = 1, Mandatory = $False)]
        [String]
        $DecoyDistinguishedName,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        [ValidateSet ("DoesNotRequirePreAuth","AllowReversiblePasswordEncryption","PasswordNeverExpires","TrustedForDelegation","TrustedToAuthForDelegation")]
        $UserFlag,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $PasswordInDescription,

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $SPN,

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        $Principal = "Everyone",

        [Parameter(Position = 7, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadProperty",

        [Parameter(Position = 8, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 9, Mandatory = $False)]
        [String]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if($DecoySamAccountName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -SAMAccountName $DecoySamAccountName).SamAccountName
    }

    elseif ($DecoyDistinguishedName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -DistinguishedName $DecoyDistinguishedName).SamAccountName
    }

    else
    {
        Write-Output "No such decoy user found."
    }
    
    if ($UserFlag)
    {
        # Set the Deocy user account userflags.
        Write-Verbose "Adding $UserFlag to decoy user $DecoySamAccountName."
        switch($UserFlag)
        {
        
            "DoesNotRequirePreAuth"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -DoesNotRequirePreAuth $true
            }
            "AllowReversiblePasswordEncryption"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -AllowReversiblePasswordEncryption $true
            }
            "PasswordNeverExpires"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -PasswordNeverExpires $true
            }
            "TrustedForDelegation"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -TrustedForDelegation $true
            }
            "TrustedToAuthForDelegation"
            {
                Set-ADAccountControl -Identity $DecoySamAccountName -TrustedToAuthForDelegation $true
            }
        }
    }

    if ($PasswordInDescription)
    {
        # Be creative! For example, "User Password is July@2018 - Last used by Gary"
        Write-Verbose "Adding $PasswordInDescription for decoy user $DecoySamAccountName."
        Set-ADUser -Identity $DecoySamAccountName -Description $PasswordInDescription
    }

    if ($SPN)
    {
        Write-Verbose "Adding $SPN to decoy user $DecoySamAccountName."
        Set-ADUser -Identity $DecoySamAccountName -ServicePrincipalNames @{Add=$SPN}
    }

    Set-AuditRUle -SAMAccountName $DecoySamAccountName -Principal $Principal -Right $Right -GUID $GUID -AuditFlag $AuditFlag -Remove $RemoveAuditing
  
}

function Deploy-SlaveDeception
{
<#
.SYNOPSIS
Deploys the specific slave user and FUllControl over it for a master user to log Security Event 4662 when a specific Right is used.

.DESCRIPTION
This function sets up auditing when a specified Right is used over the slave user by a master user who has FUllControl/GenericALl over the slave user.

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging. 

.PARAMETER SlaveSamAccountName
SamAccountName of the slave user.  

.PARAMETER SlaveDistinguishedName
DistinguishedName of the slave user.

.PARAMETER DecoySamAccountName
SamAccountName of the decoy user.

.PARAMETER DecoyDistinguishedName
DistinguishedName of the decoy user.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName master -UserLastName user -Password Pass@123 
PS C:\> Create-DecoyUser -UserFirstName slave -UserLastName user -Password Pass@123 | Deploy-SlaveDeception -DecoySamAccountName masteruser -Verbose

The first command creates a deocy user 'masteruser'.
The second command creates a decoy user 'slaveuser' and provides masteruser GenericAll rights over slaveuser.

For both the users a 4662 is logged whenever there is any interaction with them.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName master -UserLastName user -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose
PS C:\> Create-DecoyUser -UserFirstName slave -UserLastName user -Password Pass@123 | Deploy-SlaveDeception -DecoySamAccountName masteruser -Verbose
PS C:\> Deploy-SlaveDeception -SlaveSamAccountName slaveuser -DecoySamAccountName masteruser -Verbose 
The first command creates a decoy user 'masteruser' whose password never expires and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property of the user is read.
The second command creates a decoy user 'slaveuser' whose password never expires and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property of the user is read.
The third command grants masteruser GenericAll rights over slaveuser.

The above three commands make masteruser and slaveuser attractive for an attacker and the logging is triggered only for aggressive enumeration.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName master -UserLastName user -Password Pass@123
PS C:\> Create-DecoyUser -UserFirstName slave -UserLastName user -Password Pass@123 
PS C:\> Deploy-SlaveDeception -SlaveSamAccountName slaveuser -DecoySamAccountName masteruser -Verbose 
PS C:\> Deploy-UserDeception -DecoySamAccountName slaveuser -Principal masteruser -Right WriteDacl -Verbose
The first three commands create a slaveuser, create a master user and provide masteruser GenericAll rights on slaveuser.
The foruth command triggers a 4662 log only when masteruser is used change DACL (WirteDacl) of the slaveuser. 

This is useful when targeting lateral movement and it is assumed that an adversary will get access to masteruser.
For example, masteruser could be a honeyuser whose credentials are left on multipe machines or masteruser can have its
usable password in Description. 

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
[CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="SamAccountName",Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $SlaveSamAccountName,
        
        [Parameter(ParameterSetName="ADSPath",Position = 1, Mandatory = $False)]
        [String]
        $SlaveDistinguishedName,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $DecoySamAccountName,
        
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $DecoyDistinguishedName,

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if($DecoySamAccountName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -SAMAccountName $DecoySamAccountName).SamAccountName
    }

    elseif ($DecoyDistinguishedName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -DistinguishedName $DecoyDistinguishedName).SamAccountName
    }
    else
    {
        Write-Output "No such decoy user found."
    }

    if($SlaveSamAccountName)
    {
        $SlaveSamAccountName = (Get-ADObjectDetails -SAMAccountName $SlaveSamAccountName).SamAccountName
    }
    elseif ($SlaveDistinguishedName)
    {
        $SlaveSamAccountName = (Get-ADObjectDetails -DistinguishedName $SlaveDistinguishedName).SamAccountName
    }
    else
    {
        Write-Output "No such slave user found."
    }

    # Get ACL of the slave user
    $slaveuserdetails = Get-ADObjectDetails -SAMAccountName $SlaveSamAccountName
    $ACL = $slaveuserdetails.ACL

    # Set GenericALL (FullControl) rights on Slaveuser for Decoyuser
    $sid = New-Object System.Security.Principal.NTAccount($DecoySamAccountName)
    $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'GenericAll','Allow')
    $objDN = $slaveuserdetails.DistinguishedName
    $ACL.AddAccessRule($ACE)
    Set-Acl "AD:\$objDN" -AclObject $ACL

    # Add auditing for DecoyUser and Slave on ReadProperty for x500uniqueIdentifier user property.

    Set-AuditRUle -SAMAccountName $DecoySamAccountName -Principal Everyone  -Right ReadProperty -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -AuditFlag Success -RemoveAuditing $RemoveAuditing
    Set-AuditRUle -SAMAccountName $SlaveSamAccountName -Principal Everyone -Right ReadProperty -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -AuditFlag Success -RemoveAuditing $RemoveAuditing

}

function Deploy-PrivilegedUserDeception
{
<#
.SYNOPSIS
Deploys the specific decoy user and provide it high privileges (with protections) to make it interesting for an adversary.

.DESCRIPTION
This function deploys a decoy user which has high privileges like membership of the Domain Admins group. 

There are protections like nonexistent LogonWorkStation or DenyLogon to avoid abuse of these privileges. 

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging.

and 

Audit Kerberos Authentication Service for Failure needs to be enabled for 4768.

.PARAMETER DecoySamAccountName
SamAccountName of the decoy user.  

.PARAMETER DecoyDistinguishedName
DistinguishedName of the decoy user.

.PARAMETER Technique
The privilges for the decoy user. Currently, DomainAdminsMembership and DCSyncRights.

.PARAMETER Protection
Protection for avoiding abuse of the privileges. Currently, LogonWorkStation and DenyLogon.

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadControl right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER CreateLogon
Create a logon for the created decoyuser on the DC where the function is run. This helps in avoiding detection of the decoy
which relies on logoncount. A user profile is created on the DC when this parameter is used. 

.PARAMETER logonCount
Number of logonCount for the decoy user. Default is 1.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName dec -UserLastName da -Password Pass@123 | Deploy-PrivilegedUserDeception -Technique DomainAdminsMemebership -Protection DenyLogon -Verbose
Create a decoy user named decda and make it a member of the Domain Admins group. As a protection against potential abuse,
Deny logon to the user on any machine. Please be aware that if another DA gets comprimised the DenyLogon setting can be removed.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

.EXAMPLE
PS C:\> Deploy-PrivilegedUserDeception -DecoySamaccountName decda -Technique DomainAdminsMemebership -Protection LogonWorkStation nonexistent -Verbose
Use existing user decda and make it a member of the Domain Admins group. As a protection against potential abuse,
set LogonWorkstation for the user to a nonexistent machine.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

.EXAMPLE
PS C:\> Deploy-PrivilegedUserDeception -DecoySamaccountName decda -Technique DCSyncRights -Protection LogonWorkStation nonexistent -Verbose
Use existing user decda and make provide it DCSyncRights. As a protection against potential abuse,
set LogonWorkstation for the user to a nonexistent machine.

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 

.EXAMPLE
PS C:\> Create-DecoyUser -UserFirstName test -UserLastName da -Password Pass@123 | Deploy-PrivilegedUserDeception -Technique DomainAdminsMemebership -Protection LogonWorkStation -LogonWorkStation revert-dc -CreateLogon -Verbose 
Create a decoy user named decda and make it a member of the Domain Admins group. 
As a protection against potential abuse, set LogonWorkstation for the user to the DC where this function is executed. 

To avoid detection of the decoy which relies on logoncount use the CreateLogon option which starts and stops a process as the
decoy user on the DC. A user profile is created on the DC when this parameter is used. 

If there is any attempt to use the user credentials (password or hashes) a 4768 is logged.

Any enumeration which reads DACL or all properties for the user will result in a 4662 logging. 
 
.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
    [CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="SamAccountName",Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $DecoySamAccountName,

        [Parameter(ParameterSetName="ADSPath",Position = 1, Mandatory = $False)]
        [String]
        $DecoyDistinguishedName,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        [ValidateSet ("DomainAdminsMemebership","DCSyncRights")]
        $Technique,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        [ValidateSet ("LogonWorkStation","DenyLogon")]
        $Protection,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $LogonWorkStation,

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $Principal = "Everyone",

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadControl",

        [Parameter(Position = 7, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 8, Mandatory = $False)]
        [String]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Switch]
        $CreateLogon,

        [Parameter(Mandatory = $False)]
        [int]
        $logonCount = 1,

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if($DecoySamAccountName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -SAMAccountName $DecoySamAccountName).SamAccountName
    }

    elseif ($DecoyDistinguishedName)
    {
        $DecoySamAccountName = (Get-ADObjectDetails -DistinguishedName $DecoyDistinguishedName).SamAccountName
    }
    else
    {
        Write-Output "No such decoy user found."
    }


    if ($Technique)
    {
        # Set the Deocy user's interesting privileges.
        switch($Technique)
        {
            "DomainAdminsMemebership"
            {
                # The user will actually be a part of the DA group but can logon only to a non-existent workstation.
                Write-Verbose "Adding $DecoySamAccountName to the Domain Admins Group."
                Add-ADGroupMember -Identity "Domain Admins" -Members $DecoySamAccountName
                $isDA = $True
            }
            "DCSyncRights"
            {          
                # Replication Rights
                Write-Verbose "Providing DCSync permissions to $DecoySamAccountName."
                $DomainDN = (Get-AdDomain).DistinguishedName
                $ACL = Get-Acl "AD:\$DomainDN"
                $sid = New-Object System.Security.Principal.NTAccount($DecoySamAccountName)
                $objectGuidChangesAll = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidChangesAll)
                $ACL.AddAccessRule($ACE)
                Set-Acl "AD:\$DomainDN" -AclObject $ACL

                $ACL = Get-Acl "AD:\$DomainDN"
                $objectGuidChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidChanges)
                $ACL.AddAccessRule($ACE)
                Set-Acl "AD:\$DomainDN" -AclObject $ACL
            }
        }
    }

    if ($Protection)
    {
        switch ($Protection)
        {
            "LogonWorkStation"
            {
                # Set the user logon to a turned off workstation
                Write-Verbose "Adding protection - Decoy user $DecoySamAccountName can logon only to $LogonWorkStation."
                Set-ADUser -Identity $DecoySamAccountName -LogonWorkstations $LogonWorkStation
                if ($isDA -and $CreateLogon -and (Get-ADDomainController -Filter *).name -contains $LogonWorkStation )
                {
                    Write-Verbose "Creating $logonCount logon(s) on the DC for decoy domain admin $DecoySamAccountName by starting and stopping calc.exe. Please provide credentials for $DecoySamAccountName!"
                    Write-Warning "This will create a user profile for $DecoySamAccountName on $LogonWorkStation!!"
                    $creds = Get-Credential -UserName $DecoySamAccountName -Message "Please enter password for $DecoySamAccountName to create logon"
                    for ($count = 1;$count -le $logonCount;$count++)
                    {
                        Start-Process -FilePath C:\Windows\system32\calc.exe -WorkingDirectory C:\Windows\Temp -Credential $creds -PassThru | Stop-Process -Force
                        Sleep -Milliseconds 10
                    }
                }
                else
                {
                    Write-Output "Currently only Deocy DA logon creations when LogonWorkstation is set to one of the DCs is supported."
                }


            }
            "DenyLogon"
            {
                # Deny logon to user from anywhere by setting logon hours
                $Hours = New-Object byte[] 21
                $Hours[5] = 000; $Hours[8] = 000; $Hours[11] = 000; $Hours[14] = 000; $Hours[17] = 000;
                $Hours[6] = 0; $Hours[9] = 0; $Hours[12] = 0; $Hours[15] = 0; $Hours[18] = 0;
                $ReplaceHashTable = New-Object HashTable
                $ReplaceHashTable.Add("logonHours", $Hours)
                Write-Verbose "Adding protection - Decoy user $DecoySamAccountName has been denied logon."
                Set-ADUser -Identity $DecoySamAccountName -Replace $ReplaceHashTable
            }
        }
    }

    # Add auditing to the decoy user
    Set-AuditRule -UserName $DecoyUserName -SAMAccountName $DecoySamAccountName -DistinguishedName $DecoyDistinguishedName -Principal $Principal -Right $Right -GUID $GUID -AuditFlag $AuditFlag -RemoveAuditing $RemoveAuditing
    
}

function Deploy-ComputerDeception
{
<#
.SYNOPSIS
Deploys the specific decoy computer to log Security Event 4662 when a specific Right is used against it.

.DESCRIPTION
This function sets up auditing when a specified Right is used by a specifed principal against the decoy computer object.

The function must be run on a DC with domain admin privileges. There are multiple computer attributes and flags
that can be set while deploying the decoy. These attributes and flags make the decoy interesting for an attacker. 
When a right, say, ReadProperty is used to access the decoy computer, a Security Event 4662 is logged. 

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging. 

.PARAMETER DecoyComputerName
SamAccountName of the decoy computer.  

.PARAMETER OperatingSystem
OperatingSystem attribute for the decoy computer. 

.PARAMETER SPN
Set 'interesting' SPN for the decoy computer in the format servicename/host.

.PARAMETER PropertyFlag
A decoy computer property which would be 'interesting' for an attacker.

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadProperty right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyComputer -ComputerName revert-web -Verbose | Deploy-ComputerDeception -PropertyFlag TrustedForDelegation -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a  -Verbose
Creates a decoy computer that has Unconstrained Delegation enabled and a 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property or all the properties
of the computer are read.

.EXAMPLE
PS C:\> Deploy-ComputerDeception -DecoyComputerName comp1 -PropertyFlag TrustedForDelegation -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a  -Verbose
Uses an existing computer object and set Unconstrained Delegation on it. A 4662 is logged whenever x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa-76c962be719a property or all the properties
of the computer are read.

Using a real machine for the decoy is always recommended as it is harder to identify as a decoy. 


.EXAMPLE
PS C:\> Deploy-ComputerDeception -DecoyComputerName comp1 -OperatingSystem "Windows Server 2003" -Right ReadControl -Verbose
Uses an existing computer object and set its Operating System property to Windows Server 2003. 

A 4662 is logged whenever DACL or all the properties of the computer are read.

Using a real machine for the decoy is always recommended as it is harder to identify as a decoy. 

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $DecoyComputerName,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $OperatingSystem,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $SPN,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        [ValidateSet ("AllowReversiblePasswordEncryption","PasswordNeverExpires","TrustedForDelegation")]
        $PropertyFlag,


        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $Principal = "Everyone",

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadProperty",

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 7, Mandatory = $False)]
        [String]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if ($SPN)
    {
        Write-Verbose "Setting $SPN to decoy computer $DecoyComputerName."
        Set-ADComputer -Identity $DecoyComputerName -ServicePrincipalNames @{Add=$SPN}
    }

    if($OperatingSystem)
    {
        Write-Verbose "Setting $OperatingSystem to decoy computer $DecoyComputerName."
        Set-ADComputer -OperatingSystem $OperatingSystem -Identity $DecoyComputerName
    }

    if ($PropertyFlag)
    {
        # Set the Deocy computeraccount userflags.
        Write-Verbose "Setting $PropertyFlag to decoy computer $DecoyComputerName."
        switch($PropertyFlag)
        {
        
            "AllowReversiblePasswordEncryption"
            {
                Set-ADComputer -Identity $DecoyComputerName -AllowReversiblePasswordEncryption $true
            }
            "PasswordNeverExpires"
            {
                Set-ADComputer -Identity $DecoyComputerName -PasswordNeverExpires $true
            }
            "TrustedForDelegation"
            {
                Set-ADComputer -Identity $DecoyComputerName -TrustedForDelegation $true
            }
        }
    }

    # Add auditing to the decoy computer
    Set-AuditRUle -ComputerName $DecoyComputerName -Principal $Principal -Right $Right -GUID $GUID -AuditFlag $AuditFlag -RemoveAuditing $RemoveAuditing
}

function Deploy-GroupDeception
{
<#
.SYNOPSIS
Deploys the specific decoy group to log Security Event 4662 when a specific Right is used against it.

.DESCRIPTION
This function sets up auditing when a specified Right is used by a specifed principal against the decoy group object.

The function must be run on a DC with domain admin privileges. A decoy group can have members and the group can be
a member of other groups to make the decoy interesting for an attacker. 

When a right, say, ReadProperty is used to access the decoy group, a Security Event 4662 is logged. 

Note that Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access - Audit Directory Service Access
Group Policy needs to be configured to enable 4662 logging. 

.PARAMETER DecoyGroupName
SamAccountName of the decoy group.  

.PARAMETER AddMembers
Add list of Members to the decoy Group.

.PARAMETER AddToGroup
Make the decoy group a member of the specified group.

.PARAMETER Principal
The Principal (user or group) for which auditing is turned on when they use Rights defined by the Right or GUID paramter.

.PARAMETER Right
Thr Right for which auditing is turned on when used by the principal specified with the Principal parameter.
Default is ReadProperty right.

.PARAMETER GUID
GUID for the property for which auditing is turned on when Princpal uses Right on the property.

.PARAMETER AuditFlag
Turn on Auditing for Success or Failure. Default is Success.

.PARAMETER RemoveAuditing
Remove previously added Auditing ACE.

.EXAMPLE
PS C:\> Create-DecoyGroup -GroupName 'Forest Admins' -Verbose | Deploy-GroupDeception -AddMembers slaveuser -AddToGroup dnsadmins -Right ReadControl -Verbose 
Creates a decoy Group 'Forest Admins', adds slaveuser as a member and makes the group part of the dnsadmins group. 
A 4662 is logged whenever DACL or all the properties of the group are read.

.EXAMPLE
PS C:\> Create-DecoyGroup -GroupName "Forest Admins" -Verbose | Deploy-GroupDeception -AddMembers -Members slaveuser -AddToGroup -AddToGroupName dnsadmins -GUID bc0ac240-79a9-11d0-9020-00c04fc2d4cf -Verbose
Creates a decoy Group 'Forest Admins',adds slaveuser as a member and makes the group part of the dnsadmins group.
A 4662 is logged whenever membership of the Forest Admins group is listed. 

.LINK
https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
https://github.com/samratashok/Deploy-Deception
#>
    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False,ValueFromPipeline = $True)]
        [String]
        $DecoyGroupName,
     
        [Parameter(Position = 1, Mandatory = $False)]        
        [String]
        $AddMembers,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $AddToGroup,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Principal = "Everyone",

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "ReadProperty",

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $GUID,

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        [ValidateSet ("Success","Failure")]
        $AuditFlag = "Success",

        [Parameter(Mandatory = $False)]
        [Bool]
        $RemoveAuditing = $False
    )

    if ($AddMembers)
    {
        Write-Verbose "Adding members $AddMembers to $DecoyGroupName."
        Add-ADGroupMember -Identity $DecoyGroupName -Members $AddMembers
    }
    if($AddToGroup)
    {
        Write-Verbose "Adding $DecoyGroupName to $AddToGroup."
        Add-ADGroupMember -Identity $AddToGroup -Members $DecoyGroupName
    }

    # Add auditing to the decoy group
    Set-AuditRUle -GroupName $DecoyGroupName -Principal $Principal -Right $Right -GUID $GUID -AuditFlag $AuditFlag -RemoveAuditing $RemoveAuditing  
}
