-- Script: Get-ServerLogin.sql
-- Description: Get list of logins for the server.  To view all 
-- logins the user must be a sysadmin.  Unless bruteforced.
-- Reference: http://msdn.microsoft.com/en-us/library/ms345412.aspx

SELECT name,
	principal_id,
	sid,
	type,
	type_desc,
	create_date, 
	LOGINPROPERTY ( name , 'IsLocked' ) AS [is_locked]
FROm [sys].[server_principals]