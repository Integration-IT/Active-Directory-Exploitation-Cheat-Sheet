-- Script: Get-AuditAction.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns available audit actions. 
-- Reference: https://msdn.microsoft.com/en-us/library/cc280725.aspx

SELECT DISTINCT action_id,name,class_desc,parent_class_desc,containing_group_name 
FROM sys.dm_audit_actions 
ORDER BY parent_class_desc,containing_group_name,name
