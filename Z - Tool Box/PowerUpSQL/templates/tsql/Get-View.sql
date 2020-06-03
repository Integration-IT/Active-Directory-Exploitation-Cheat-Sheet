-- Script: Get-View.sql
-- Description: This script returns a list of view
--	from the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms186778.aspx

SELECT TABLE_CATALOG AS [DATABASE_NAME],
	TABLE_SCHEMA AS [SCHEMA_NAME],
	TABLE_NAME,
	VIEW_DEFINITION,
	IS_UPDATABLE
FROM [INFORMATION_SCHEMA].[VIEWS]
ORDER BY DATABASE_NAME,SCHEMA_NAME,TABLE_NAME