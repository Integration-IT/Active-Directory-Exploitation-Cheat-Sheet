#requires -Modules ActiveDirectory 

function Set-ADACL
{

    [CmdletBinding()] Param(
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $SAMAccountName,
        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $DistinguishedName,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Principal,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        [ValidateSet ("GenericAll","WriteDacl","WriteOwner","WriteProperty")]
        $Right = "GenericAll",

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        [ValidateSet ("DCSync","Other")]
        $GUIDRight,
        
        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        [ValidateSet ("Allow","Deny")]
        $Type = "Allow"

    )
    
    if ($SAMAccountName)
    {
        $objDN = (Get-ADUser -Identity $SamAccountName).distinguishedname
    }
    elseif ($DistinguishedName)
    {
        $objDN = $DistinguishedName
    }
    else
    {
        Write-Output 'Cannot find the object.'
    }
    Write-Verbose "Getting the existing ACL for $objDN."
    $ACL = Get-Acl -Path "AD:\$objDN"
    $sid = New-Object System.Security.Principal.NTAccount($Principal)

    if ($GUIDRight -eq "DCSync")
    {
        # DS-Replication-Get-Changes
        $objectGuidGetChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ACL.AddAccessRule($ACEGetChanges)

        # DS-Replication-Get-Changes-All
        $objectGuidGetChangesAll = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChangesAll = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChangesAll)
        $ACL.AddAccessRule($ACEGetChangesAll)
   
        # DS-Replication-Get-Changes-In-Filtered-Set
        $objectGuidGetChangesFiltered = New-Object Guid 89e95b76-444d-4c62-991a-0facbeda640c
        $ACEGetChangesFiltered = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChangesFiltered)
        $ACL.AddAccessRule($ACEGetChangesFiltered)
    }
    else
    {
        $ACE = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,$Right,$Type)
        $ACL.AddAccessRule($ACE)
    }


    Write-Verbose "Setting ACL for ""$objDN"" for ""$Principal"" to use ""$Right"" right."
    Set-Acl "AD:\$objDN" -AclObject $ACL

}