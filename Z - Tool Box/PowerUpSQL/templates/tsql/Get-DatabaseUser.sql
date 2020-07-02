-- Script: Get-DatabaseUser.sql
-- Description: Get list of users for the current database.  To view all 
--  users you may need to be a sysadmin.  Unless bruteforced.
-- Reference: https://msdn.microsoft.com/en-us/library/ms187328.aspx
-- Join Ref: http://blog.sqlauthority.com/2009/04/13/sql-server-introduction-to-joins-basic-of-joins/

SELECT 
	a.principal_id,
	a.name as [database_user],
	b.name as [sql_login],
	a.type,
	a.type_desc,
	default_schema_name,
	a.sid,
	a.create_date,
	a.is_fixed_role
FROM [sys].[database_principals] a
LEFT JOIN [sys].[server_principals] b
	ON a.sid = b.sid
ORDER BY principal_id
