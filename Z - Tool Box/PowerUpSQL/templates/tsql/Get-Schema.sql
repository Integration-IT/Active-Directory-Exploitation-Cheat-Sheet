-- Script: Get-Schema.sql
-- Description: Return list of schemas for the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms182642.aspx

SELECT CATALOG_NAME AS [DATABASE_NAME],
	SCHEMA_NAME,
	SCHEMA_OWNER
FROM [INFORMATION_SCHEMA].[SCHEMATA]
ORDER BY SCHEMA_NAME