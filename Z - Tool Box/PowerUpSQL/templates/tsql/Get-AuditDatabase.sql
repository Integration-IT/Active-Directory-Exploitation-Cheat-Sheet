-- Script: Get-AuditDatabase.sql
-- Description: Return a list audit database specifications.
-- Reference: https://technet.microsoft.com/en-us/library/ms190227(v=sql.110).aspx

SELECT	a.audit_id,
	a.name as audit_name,
	s.name as database_specification_name,
	d.audit_action_name,
	d.major_id,
	OBJECT_NAME(d.major_id) as object,	
	s.is_state_enabled,
	d.is_group,
	s.create_date,
	s.modify_date,
	d.audited_result
FROM sys.server_audits AS a
JOIN sys.database_audit_specifications AS s
ON a.audit_guid = s.audit_guid
JOIN sys.database_audit_specification_details AS d
ON s.database_specification_id = d.database_specification_id
