-- Use this to list out CLR stored procedure information
-- This is a modified version of code found at 
-- https://stackoverflow.com/questions/3155542/sql-server-how-to-list-all-clr-functions-procedures-objects-for-assembly
USE msdb;
SELECT      SCHEMA_NAME(so.[schema_id]) AS [schema_name], 
			af.file_id,					  	
			af.name + '.dll' as [file_name],
			asmbly.clr_name,
			asmbly.assembly_id,           
			asmbly.name AS [assembly_name], 
			am.assembly_class,
			am.assembly_method,
			so.object_id as [sp_object_id],
			so.name AS [sp_name],
			so.[type] as [sp_type],
			asmbly.permission_set_desc,
			asmbly.create_date,
			asmbly.modify_date,
			af.content								           
FROM        sys.assembly_modules am
INNER JOIN  sys.assemblies asmbly
ON  	    asmbly.assembly_id = am.assembly_id
INNER JOIN  sys.assembly_files af 
ON 	    asmbly.assembly_id = af.assembly_id 
INNER JOIN  sys.objects so
ON  	    so.[object_id] = am.[object_id]
