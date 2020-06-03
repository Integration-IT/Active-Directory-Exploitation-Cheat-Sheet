-- Requirement: R must be setup during the installation.

-- Enable advanced options
sp_configure 'show advanced options',1
reconfigure
go

-- Enable external scripts
-- Requires a restart of the SQL Server service to take effect
-- User must have "EXECUTE ANY EXTERNAL SCRIPT" privilege
sp_configure 'external scripts enabled',1
reconfigure WITH OVERRIDE
go

EXEC sp_execute_external_script
  @language=N'R',
  @script=N'OutputDataSet <- data.frame(system("cmd.exe /c dir",intern=T))'
  WITH RESULT SETS (([cmd_out] text));
GO

-- Disable external scripts
-- Requires a restart of the SQL Server service to take effect
sp_configure 'external scripts enabled',0
reconfigure WITH OVERRIDE
go

-- Disable advanced options
sp_configure 'show advanced options',0
reconfigure
go
