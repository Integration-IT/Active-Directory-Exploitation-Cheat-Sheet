
<#
Import this module to load all the functions in Deploy-Deception in the current PowerShell session.

PS > Import-Module C:\Deploy-Deception\Deploy-Deception.psm1

#>


if(!$PSScriptRoot)
{ 
    $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}
$PSScriptRoot
Get-ChildItem -Recurse $PSScriptRoot *.ps1  | ForEach-Object  {. $_.FullName}

