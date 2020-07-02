-- Script: Get-Session.sql
-- Description: Get current login sessions.
-- Reference: https://msdn.microsoft.com/en-us/library/ms176013.aspx

SELECT 
	status,
	session_id,
	login_time,
	last_request_start_time,
	security_id,
	login_name,
	original_login_name
FROM [sys].[dm_exec_sessions]
ORDER BY status