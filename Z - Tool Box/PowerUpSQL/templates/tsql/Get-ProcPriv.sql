-- Script: Get-ProcPriv.sql
-- Description: Return list of privileges for procedures in current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms188367.aspx

SELECT b.name AS [DATABASE_USER], 
	c.name AS [DATABASE_OBJECT_NAME],  
	a.permission_name AS [OBJECT_PERMISSION]
FROM [sys].[database_permissions] a
INNER JOIN [sys].[sysusers] b
	ON a.[grantee_principal_id] = b.[uid] 
INNER JOIN [sys].[sysobjects] c
	ON a.[major_id] = c.[id]
ORDER BY [DATABASE_USER],[DATABASE_OBJECT_NAME]