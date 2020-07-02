# Edits by Tim Medin
# File:     GetUserSPNS.ps1
# Contents: Query the domain to find SPNs that use User accounts
# Comments: This is for use with Kerberoast https://github.com/nidem/kerberoast
#           The password hash used with Computer accounts are infeasible to 
#           crack; however, if the User account associated with an SPN may have
#           a crackable password. This tool will find those accounts. You do not
#           need any special local or domain permissions to run this script. 
#           This script on a script supplied by Microsoft (details below).
# History:    2014/11/12     Tim Medin    Created

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False,Position=1)] [string]$GCName,
  [Parameter(Mandatory=$False)] [string]$Filter
)

$GCs = @()

If ($GCName) {
  $GCs += $GCName
} else { # find them
  $ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $CurrentGCs = $ForestInfo.FindAllGlobalCatalogs()
  ForEach ($GC in $CurrentGCs) {
    #$GCs += $GC.Name
    $GCs += $ForestInfo.ApplicationPartitions[0].SecurityReferenceDomain
  }
}

if (-not $GCs) {
  # no Global Catalogs Found
  Write-Host "No Global Catalogs Found!"
  Exit
}

<#
Things you can extract
Name                           Value
----                           -----
admincount                     {1}
samaccountname                 {sqlengine}
useraccountcontrol             {66048}
primarygroupid                 {513}
userprincipalname              {sqlengine@medin.local}
instancetype                   {4}
displayname                    {sqlengine}
pwdlastset                     {130410454241766739}
memberof                       {CN=Domain Admins,CN=Users,DC=medin,DC=local}
samaccounttype                 {805306368}
serviceprincipalname           {MSSQLSvc/sql01.medin.local:1433, MSSQLSvc/sql01.medin.local}
usnchanged                     {135252}
lastlogon                      {130563243107145358}
accountexpires                 {9223372036854775807}
logoncount                     {34}
adspath                        {LDAP://CN=sqlengine,CN=Users,DC=medin,DC=local}
distinguishedname              {CN=sqlengine,CN=Users,DC=medin,DC=local}
badpwdcount                    {0}
codepage                       {0}
name                           {sqlengine}
whenchanged                    {9/22/2014 6:45:21 AM}
badpasswordtime                {0}
dscorepropagationdata          {4/4/2014 2:16:44 AM, 4/4/2014 12:58:27 AM, 4/4/2014 12:37:04 AM,...
lastlogontimestamp             {130558419213902030}
lastlogoff                     {0}
objectclass                    {top, person, organizationalPerson, user}
countrycode                    {0}
cn                             {sqlengine}
whencreated                    {4/4/2014 12:37:04 AM}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 191 250 179 30 180 59 104 26 248 205 17...
objectguid                     {101 165 206 61 61 201 88 69 132 246 108 227 231 47 109 102}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=medin,DC=local}
usncreated                     {57551}
#>

ForEach ($GC in $GCs) {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://" + $GC
    $searcher.PageSize = 1000
    $searcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    #$searcher.PropertiesToLoad.Add("userprincipalname") | Out-Null
    #$searcher.PropertiesToLoad.Add("displayname") | Out-Null
    $searcher.PropertiesToLoad.Add("memberof") | Out-Null
    $searcher.PropertiesToLoad.Add("pwdlastset") | Out-Null
    #$searcher.PropertiesToLoad.Add("distinguishedname") | Out-Null

    $searcher.SearchScope = "Subtree"

    $results = $searcher.FindAll()
        
    foreach ($result in $results) {
        foreach ($spn in $result.Properties["serviceprincipalname"]) {
            Select-Object -InputObject $result -Property `
                @{Name="ServicePrincipalName"; Expression={$spn.ToString()} }, `
                @{Name="Name";                 Expression={$result.Properties["name"][0].ToString()} }, `
                #@{Name="UserPrincipalName";    Expression={$result.Properties["userprincipalname"][0].ToString()} }, `
                #@{Name="DisplayName";          Expression={$result.Properties["displayname"][0].ToString()} }, `
                @{Name="MemberOf";             Expression={$result.Properties["memberof"][0].ToString()} }, `
                @{Name="PasswordLastSet";      Expression={[datetime]::fromFileTime($result.Properties["pwdlastset"][0])} } #, `
                #@{Name="DistinguishedName";    Expression={$result.Properties["distinguishedname"][0].ToString()} }
          }
    }
}
