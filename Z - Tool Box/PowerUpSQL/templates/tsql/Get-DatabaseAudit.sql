-- Script: Get-DatabaseAudit.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns database audit specifications. 
-- Reference: https://msdn.microsoft.com/en-us/library/cc280726.aspx

SELECT * FROM sys.server_audits AS a
JOIN sys.database_audit_specifications AS s
ON a.audit_guid = s.audit_guid
JOIN sys.database_audit_specification_details AS d
ON s.database_specification_id = d.database_specification_id
