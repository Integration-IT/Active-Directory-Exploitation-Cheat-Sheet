USE [msdb]
GO

/****** Object:  Job [OS COMMAND EXECUTION EXAMPLE - ActiveX: VBSCRIPT]    Script Date: 8/29/2017 10:27:36 AM ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 8/29/2017 10:27:36 AM ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
DECLARE @user varchar(8000)
SET @user = SYSTEM_USER
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'OS COMMAND EXECUTION EXAMPLE - ActiveX: VBSCRIPT', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=1, 
		@description=N'No description available.', 
		@category_name=N'[Uncategorized (Local)]', 
		@owner_login_name=@user, @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [RUN COMMAND - ActiveX: VBSCRIPT]    Script Date: 8/29/2017 10:27:36 AM ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'RUN COMMAND - ActiveX: VBSCRIPT', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'ActiveScripting', 
		@command=N'FUNCTION Main()

dim shell
set shell= CreateObject ("WScript.Shell")
shell.run("c:\windows\system32\cmd.exe /c echo hello > c:\windows\temp\blah.txt")
set shell = nothing

END FUNCTION', 
		@database_name=N'VBScript', 
		@flags=0
		--,@proxy_name=N'WinUser1'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO

use msdb
EXEC dbo.sp_start_job N'OS COMMAND EXECUTION EXAMPLE - ActiveX: VBSCRIPT' ;  
