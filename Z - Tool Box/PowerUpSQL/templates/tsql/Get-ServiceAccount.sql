-- Script: Get-ServiceAccount.sql
-- Description: Return the service accounts running the major database services.

-- Setup variables
DECLARE		@SQLServerInstance	VARCHAR(250)  
DECLARE		@MSOLAPInstance		VARCHAR(250) 
DECLARE		@ReportInstance 	VARCHAR(250) 
DECLARE		@AgentInstance	 	VARCHAR(250) 
DECLARE		@IntegrationVersion	VARCHAR(250)
DECLARE		@DBEngineLogin		VARCHAR(100)
DECLARE		@AgentLogin		VARCHAR(100)
DECLARE		@BrowserLogin		VARCHAR(100)
DECLARE     	@WriterLogin		VARCHAR(100)
DECLARE		@AnalysisLogin		VARCHAR(100)
DECLARE		@ReportLogin		VARCHAR(100)
DECLARE		@IntegrationDtsLogin	VARCHAR(100)

-- Get Service Paths for default and name instance
if @@SERVICENAME = 'MSSQLSERVER' or @@SERVICENAME = HOST_NAME()
BEGIN											
	-- Default instance paths
	set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
	set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLServerOLAPService'	
	set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer'
	set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT'	
	set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
END						
ELSE
BEGIN
	-- Named instance paths
	set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$' + cast(@@SERVICENAME as varchar(250))	
	set @MSOLAPInstance = 'SYSTEM\CurrentControlSet\Services\MSOLAP$' + cast(@@SERVICENAME as varchar(250))		
	set @ReportInstance = 'SYSTEM\CurrentControlSet\Services\ReportServer$' + cast(@@SERVICENAME as varchar(250))
	set @AgentInstance = 'SYSTEM\CurrentControlSet\Services\SQLAgent$' + cast(@@SERVICENAME as varchar(250))	
	set @IntegrationVersion  = 'SYSTEM\CurrentControlSet\Services\MsDtsServer'+ SUBSTRING(CAST(SERVERPROPERTY('productversion') AS VARCHAR(255)),0, 3) + '0'
END

-- Get SQL Server - Calculated
EXECUTE		master.dbo.xp_instance_regread  
		N'HKEY_LOCAL_MACHINE', @SQLServerInstance,  
		N'ObjectName',@DBEngineLogin OUTPUT

-- Get SQL Server Agent - Calculated
EXECUTE		master.dbo.xp_instance_regread  
		N'HKEY_LOCAL_MACHINE', @AgentInstance,  
		N'ObjectName',@AgentLogin OUTPUT

-- Get SQL Server Browser - Static Location
EXECUTE       master.dbo.xp_instance_regread
              @rootkey      = N'HKEY_LOCAL_MACHINE',
              @key          = N'SYSTEM\CurrentControlSet\Services\SQLBrowser',
              @value_name   = N'ObjectName',
              @value        = @BrowserLogin OUTPUT

-- Get SQL Server Writer - Static Location
EXECUTE       master.dbo.xp_instance_regread
              @rootkey      = N'HKEY_LOCAL_MACHINE',
              @key          = N'SYSTEM\CurrentControlSet\Services\SQLWriter',
              @value_name   = N'ObjectName',
              @value        = @WriterLogin OUTPUT

-- Get MSOLAP - Calculated
EXECUTE		master.dbo.xp_instance_regread  
		N'HKEY_LOCAL_MACHINE', @MSOLAPInstance,  
		N'ObjectName',@AnalysisLogin OUTPUT

-- Get Reporting - Calculated
EXECUTE		master.dbo.xp_instance_regread  
		N'HKEY_LOCAL_MACHINE', @ReportInstance,  
		N'ObjectName',@ReportLogin OUTPUT

-- Get SQL Server DTS Server / Analysis - Calulated
EXECUTE		master.dbo.xp_instance_regread  
		N'HKEY_LOCAL_MACHINE', @IntegrationVersion,  
		N'ObjectName',@IntegrationDtsLogin OUTPUT

-- Dislpay results
SELECT		[DBEngineLogin] = @DBEngineLogin, 
		[BrowserLogin] = @BrowserLogin,
		[AgentLogin] = @AgentLogin,
		[WriterLogin] = @WriterLogin,
		[AnalysisLogin] = @AnalysisLogin,
		[ReportLogin] = @ReportLogin,
		[IntegrationLogin] = @IntegrationDtsLogin
GO

