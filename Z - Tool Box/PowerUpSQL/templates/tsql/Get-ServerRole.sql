-- Script: Get-ServerRole.sql
-- Description: Return security principals and server roles.
-- Reference: https://msdn.microsoft.com/en-us/library/ms188786.aspx

SELECT sp.name AS LoginName,
	sp.type_desc AS LoginType, 
	sp.default_database_name AS DefaultDBName,
	slog.sysadmin AS SysAdmin,
	slog.securityadmin AS SecurityAdmin,
	slog.serveradmin AS ServerAdmin, 
	slog.setupadmin AS SetupAdmin, 
	slog.processadmin AS ProcessAdmin, 
	slog.diskadmin AS DiskAdmin, 
	slog.dbcreator AS DBCreator,
	slog.bulkadmin AS BulkAdmin
FROM [sys].[server_principals] sp
JOIN [master].[dbo].[syslogins] slog
ON sp.sid = slog.sid 