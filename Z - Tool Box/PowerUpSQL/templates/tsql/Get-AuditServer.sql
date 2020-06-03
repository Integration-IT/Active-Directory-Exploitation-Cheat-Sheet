-- Script: Get-AuditServer.sql
-- Description: Return a list audit server specifications.
-- Reference: https://technet.microsoft.com/en-us/library/cc280663(v=sql.105).aspx

SELECT	audit_id, 
		a.name as audit_name, 
		s.name as server_specification_name,
		d.audit_action_name,
		s.is_state_enabled,
		d.is_group,
		d.audit_action_id,	
		s.create_date,
		s.modify_date
FROM sys.server_audits AS a
JOIN sys.server_audit_specifications AS s
ON a.audit_guid = s.audit_guid
JOIN sys.server_audit_specification_details AS d
ON s.server_specification_id = d.server_specification_id
