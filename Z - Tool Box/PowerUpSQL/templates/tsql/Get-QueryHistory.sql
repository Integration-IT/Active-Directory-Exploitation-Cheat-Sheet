-- Script: Get-QueryHistory.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns queries executed on the system.  It should include all queries since the service was started. 
-- Reference: http://blogs.lessthandot.com/index.php/datamgmt/dbprogramming/finding-out-how-many-times-a-table-is-be-2008/

SELECT * FROM 
	(SELECT 
	COALESCE(OBJECT_NAME(qt.objectid),'Ad-Hoc') AS objectname,
	qt.objectid as objectid,
	last_execution_time,
	execution_count,
	encrypted,
    (SELECT TOP 1 SUBSTRING(qt.TEXT,statement_start_offset / 2+1,( (CASE WHEN statement_end_offset = -1 THEN (LEN(CONVERT(NVARCHAR(MAX),qt.TEXT)) * 2) ELSE statement_end_offset END)- statement_start_offset) / 2+1)) AS sql_statement
	FROM sys.dm_exec_query_stats AS qs
	CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS qt ) x
ORDER BY execution_count DESC
