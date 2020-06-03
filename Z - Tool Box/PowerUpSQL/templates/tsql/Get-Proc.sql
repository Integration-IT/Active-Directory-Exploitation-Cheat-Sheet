-- Script: Get-Proc.sql
-- Description: Return a list of procedures for the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms188757.aspx

SELECT ROUTINE_CATALOG AS [DATABASE_NAME],
	ROUTINE_SCHEMA AS [SCHEMA_NAME],
	ROUTINE_NAME,
	ROUTINE_TYPE,
	ROUTINE_DEFINITION,
	SQL_DATA_ACCESS,
	ROUTINE_BODY,
	CREATED,
	LAST_ALTERED
FROM [INFORMATION_SCHEMA].[ROUTINES]
