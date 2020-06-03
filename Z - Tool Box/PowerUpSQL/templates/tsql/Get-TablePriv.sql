-- Script: Get-TablePriv.sql
-- Description: Returns a list of explicit table privileges for the 
--	current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms186233.aspx

SELECT GRANTOR,
	GRANTEE,
	TABLE_CATALOG AS [DATABASE_NAME],
	TABLE_SCHEMA AS [SCHEMA_NAME],
	TABLE_NAME,
	PRIVILEGE_TYPE,
	IS_GRANTABLE
FROM [INFORMATION_SCHEMA].[TABLE_PRIVILEGES]