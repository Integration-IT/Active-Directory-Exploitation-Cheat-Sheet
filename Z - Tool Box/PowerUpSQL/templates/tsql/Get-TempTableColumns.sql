-- List temp tables, columns, and column types
SELECT t1.name as 'Table_Name',
	   t2.name as 'Column_Name',
	   t3.name as 'Column_Type',
	   t1.create_date,
	   t1.modify_date,
	   t1.parent_object_id,
	   OBJECT_ID(t1.parent_object_id) as parent_object,
	   (SELECT CASE WHEN (select len(t1.name) - len(replace(t1.name,'#',''))) > 1 THEN 1 ELSE 0 END) as GlobalTempTable, 
	   (SELECT CASE WHEN t1.name like '%[_]%' AND (select len(t1.name) - len(replace(t1.name,'#',''))) = 1 THEN 1 ELSE 0 END) as LocalTempTable,
	   (SELECT CASE WHEN t1.name not like '%[_]%' AND (select len(t1.name) - len(replace(t1.name,'#',''))) = 1 THEN 1 ELSE 0 END) as TableVariable
FROM tempdb.sys.objects AS t1
JOIN tempdb.sys.columns AS t2 ON t1.OBJECT_ID = t2.OBJECT_ID
JOIN sys.types AS t3 ON t2.system_type_id = t3.system_type_id
WHERE t1.name like '#%';
