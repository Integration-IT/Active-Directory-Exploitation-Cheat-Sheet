-- Script: Get-DatabaseRole.sql
-- Description: This script with return database
--	users and roles for current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms187328.aspx

SELECT  db_name() AS [DatabaseName],
	a.name AS [PrincipalName],
	a.type_desc AS [PrincipalType],
	USER_NAME(b.role_principal_id) AS [DatabaseRole],
	a.is_fixed_role [is_fixed_role]
FROM [sys].[database_principals] a
LEFT OUTER JOIN [sys].[database_role_members] b
ON a.principal_id = b.member_principal_id 
WHERE a.sid IS NOT NULL
ORDER BY [DatabaseName]
