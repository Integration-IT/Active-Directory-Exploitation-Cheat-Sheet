-- Script: Get-TriggerDDL.sql 
-- Description: Return list of DDL triggers at the server level.  
-- This must be run with the master database select to get the trigger definition.

SELECT	name,
	OBJECT_DEFINITION(OBJECT_ID) as trigger_definition,
	parent_class_desc,
	create_date,
	modify_date,
	is_ms_shipped,
	is_disabled
FROM sys.server_triggers

