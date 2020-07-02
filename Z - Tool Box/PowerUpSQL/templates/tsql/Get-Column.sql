-- Script: Get-Column.sql
-- Description: Get list of columns for the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms188348.aspx

SELECT TABLE_CATALOG AS [DATABASE_NAME],
	TABLE_SCHEMA as [SCHEMA_NAME],
	TABLE_NAME,COLUMN_NAME,
	DATA_TYPE 
FROM [INFORMATION_SCHEMA].[COLUMNS]
