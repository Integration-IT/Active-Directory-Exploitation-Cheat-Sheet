-- Script: Get-GlobalTempTableColumns.sql
-- Description: This can be used to monitor for global temp tables and their columns as a least privilege user.
-- Author: Scott Sutherland

-- Loop
While 1=1
BEGIN

	-- List global temp tables, columns, and column types
	SELECT t1.name as 'Table_Name',
		   t2.name as 'Column_Name',
		   t3.name as 'Column_Type',
		   t1.create_date,
		   t1.modify_date,
		   t1.parent_object_id	   
	FROM tempdb.sys.objects AS t1
	JOIN tempdb.sys.columns AS t2 ON t1.OBJECT_ID = t2.OBJECT_ID
	JOIN sys.types AS t3 ON t2.system_type_id = t3.system_type_id
	WHERE (select len(t1.name) - len(replace(t1.name,'#',''))) > 1

	-- Set delay
	WaitFor Delay '00:00:01'
  
END
