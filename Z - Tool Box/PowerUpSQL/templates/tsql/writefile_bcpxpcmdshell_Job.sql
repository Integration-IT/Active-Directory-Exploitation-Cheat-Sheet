-- Create the job, run the job every minute
-- TSQL: create powershell script that outputs file to log directory, run powershell script
-- This is just a template.

USE [msdb]
GO

BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0

IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'RunMyPowerShellJob', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'[Uncategorized (Local)]', 
		@owner_login_name=N'sa', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'RunPowerShellJobStep', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'TSQL', 
		@command=N'---------------------------------------
-- Script: writefile_bcpxpcmdshell.sql
-- Author/Modifications: Scott Sutherland
-- Based on https://www.simple-talk.com/sql/t-sql-programming/the-tsql-of-text-files/ 
-- Description:
-- Write PowerShell code to disk and run it using bcp and xp_cmdshell.
---------------------------------------

-- Enable xp_cmdshell
sp_configure ''show advanced options'',1
RECONFIGURE
GO

sp_configure ''xp_cmdshell'',1
RECONFIGURE
GO

-- Create variables
DECLARE @MyPowerShellCode NVARCHAR(MAX)
DECLARE @PsFileName NVARCHAR(4000)
DECLARE @TargetDirectory NVARCHAR(4000)
DECLARE @PsFilePath NVARCHAR(4000)
DECLARE @MyGlobalTempTable NVARCHAR(4000)
DECLARE @Command NVARCHAR(4000)

-- Set filename for PowerShell script
Set @PsFileName = ''MyPowerShellScript.ps1''

-- Set target directory for PowerShell script to be written to
SELECT  @TargetDirectory = REPLACE(CAST((SELECT SERVERPROPERTY(''ErrorLogFileName'')) as VARCHAR(MAX)),''ERRORLOG'','''')

-- Create full output path for creating the PowerShell script 
SELECT @PsFilePath = @TargetDirectory +  @PsFileName
SELECT @PsFilePath as PsFilePath

-- Define the PowerShell code
SET @MyPowerShellCode = ''Write-Output "hello world" | Out-File "'' +  @TargetDirectory + ''intendedoutput.txt"''
SELECT @MyPowerShellCode as PsScriptCode

-- Create a global temp table with a unique name using dynamic SQL 
SELECT  @MyGlobalTempTable =  ''##temp'' + CONVERT(VARCHAR(12), CONVERT(INT, RAND() * 1000000))

-- Create a command to insert the PowerShell code stored in the @MyPowerShellCode variable, into the global temp table
SELECT  @Command = ''
		CREATE TABLE ['' + @MyGlobalTempTable + ''](MyID int identity(1,1), PsCode varchar(MAX)) 
		INSERT INTO  ['' + @MyGlobalTempTable + ''](PsCode) 
		SELECT @MyPowerShellCode''
				
-- Execute that command 
EXECUTE sp_ExecuteSQL @command, N''@MyPowerShellCode varchar(MAX)'', @MyPowerShellCode

-- Add delay for lab race condition - Change as needed
WAITFOR DELAY ''00:00:5''

-- Execute bcp via xp_cmdshell (as the service account) to save the contents of the temp table to MyPowerShellScript.ps1
SELECT @Command = ''bcp "SELECT PsCode from ['' + @MyGlobalTempTable + '']'' + ''" queryout "''+ @PsFilePath + ''" -c -T -S '' + @@SERVERNAME

-- Write the file
EXECUTE MASTER..xp_cmdshell @command, NO_OUTPUT

-- Drop the global temp table
EXECUTE ( ''Drop table '' + @MyGlobalTempTable )

-- Run the PowerShell script
DECLARE @runcmdps nvarchar(4000)
SET @runcmdps = ''Powershell -C "$x = gc ''''''+ @PsFilePath + '''''';iex($X)"''
EXECUTE MASTER..xp_cmdshell @runcmdps, NO_OUTPUT

-- Delete the PowerShell script
DECLARE @runcmddel nvarchar(4000)
SET @runcmddel= ''DEL /Q "'' + @PsFilePath +''"''
EXECUTE MASTER..xp_cmdshell @runcmddel, NO_OUTPUT
', 
		@database_name=N'master', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'RunPsJobEveryMinute', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=4, 
		@freq_subday_interval=1, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20191105, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'6c1e63cf-1a5b-4fe4-a271-7aa247b50c73'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO
