-- Script: Get-ServerAudit.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: List server audit specifications. 
-- Reference: https://msdn.microsoft.com/en-us/library/cc280727.aspx

SELECT * FROM sys.server_audits AS a
JOIN sys.server_audit_specifications AS s
ON a.audit_guid = s.audit_guid
JOIN sys.server_audit_specification_details AS d
ON s.server_specification_id = d.server_specification_id
