-- Script: Get-Table.sql
-- Description: Returns a list of tables for the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms186224.aspx

SELECT TABLE_CATALOG AS [DATABASE_NAME],
	TABLE_SCHEMA AS [SCHEMA_NAME],
	TABLE_NAME,TABLE_TYPE
FROM [INFORMATION_SCHEMA].[TABLES]