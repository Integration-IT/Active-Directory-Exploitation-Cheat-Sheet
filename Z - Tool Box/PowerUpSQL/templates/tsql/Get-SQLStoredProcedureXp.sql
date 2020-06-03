/*
  Script: Get-SQLStoredProcedureXP.sql
  Description: This will list the custom exteneded stored procedures for the current database.
  Author: Scott Sutherland, 2017
*/

SELECT	o.object_id,
		o.parent_object_id,
		o.schema_id,
		o.type,
		o.type_desc,
		o.name,
		o.principal_id,
		s.text,
		s.ctext,
		s.status,
		o.create_date,
		o.modify_date,
		o.is_ms_shipped,
		o.is_published,
		o.is_schema_published,
		s.colid,
		s.compressed,
		s.encrypted,
		s.id,
		s.language,
		s.number,
		s.texttype
FROM sys.objects o 
INNER JOIN sys.syscomments s
		ON o.object_id = s.id
WHERE o.type = 'x' 
