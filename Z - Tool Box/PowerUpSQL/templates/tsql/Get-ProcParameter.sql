-- Script: Get-ProcParameter.sql
-- Description: Return stored procedures and parameter information 
--	for the current database.
-- Reference: https://msdn.microsoft.com/en-us/library/ms190324.aspx
-- Reference: http://www.mssqltips.com/sqlservertip/1669/generate-a-parameter-list-for-all-sql-server-stored-procedures-and-functions/
-- or just select * from INFORMATION_SCHEMA.PARAMETERS

SELECT DB_NAME() as [DATABASE_NAME],
	SCHEMA_NAME(SCHEMA_ID) AS [SCHEMA_NAME],
	SO.name AS [ObjectName],
	SO.Type_Desc AS [ObjectType (UDF/SP)],
	P.parameter_id AS [ParameterID],
	P.name AS [ParameterName],
	TYPE_NAME(P.user_type_id) AS [ParameterDataType],
	P.max_length AS [ParameterMaxBytes],
	P.is_output AS [IsOutPutParameter]
FROM sys.objects AS SO
INNER JOIN sys.parameters AS P
ON SO.OBJECT_ID = P.OBJECT_ID
WHERE SO.OBJECT_ID IN ( SELECT OBJECT_ID
	FROM sys.objects
	WHERE TYPE IN ('P','FN'))
ORDER BY [SCHEMA_NAME], SO.name, P.parameter_id