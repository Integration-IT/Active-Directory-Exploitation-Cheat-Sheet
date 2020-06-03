-- Script: Get-CachedPlans.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns a row for each query plan that has been cached by SQL Server for faster query execution since the service started.
-- Reference: https://msdn.microsoft.com/en-us/library/ms187404.aspx

SELECT  bucketid,plan_handle,size_in_bytes,cacheobjtype,objtype,dbid,DB_NAME(dbid) as DatabaseName,objectid,OBJECT_NAME(objectid) as ObjectName,refcounts,usecounts,number,encrypted,text
FROM sys.dm_exec_cached_plans AS p
CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) AS t
ORDER BY usecounts DESC

