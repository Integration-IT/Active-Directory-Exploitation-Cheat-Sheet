-- Script: Get-TriggerDML.sql 
-- Return list of DML triggers at the database level for the current database. 

SELECT	@@SERVERNAME as server_name,
	(SELECT TOP 1 SCHEMA_NAME(schema_id)FROM sys.objects WHERE type ='tr' and object_id like object_id ) as schema_id ,
	DB_NAME() as database_name,
	OBJECT_NAME(parent_id) as parent_name,
	OBJECT_NAME(object_id) as trigger_name,
	OBJECT_DEFINITION(object_id) as trigger_definition,
	OBJECT_ID,
	create_date,
	modify_date,
	CASE OBJECTPROPERTY(object_id, 'ExecIsTriggerDisabled')
          WHEN 1 THEN 'Disabled'
          ELSE 'Enabled'
        END AS status,
	OBJECTPROPERTY(object_id, 'ExecIsUpdateTrigger') AS isupdate ,
        OBJECTPROPERTY(object_id, 'ExecIsDeleteTrigger') AS isdelete ,
        OBJECTPROPERTY(object_id, 'ExecIsInsertTrigger') AS isinsert ,
        OBJECTPROPERTY(object_id, 'ExecIsAfterTrigger') AS isafter ,
        OBJECTPROPERTY(object_id, 'ExecIsInsteadOfTrigger') AS isinsteadof ,
	is_ms_shipped,
	is_not_for_replication
FROM sys.triggers


