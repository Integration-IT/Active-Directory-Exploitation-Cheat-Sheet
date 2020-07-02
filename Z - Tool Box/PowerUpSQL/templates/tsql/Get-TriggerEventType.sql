-- Script: Get-TriggerEventType.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns trigger event types. 
-- Reference: https://msdn.microsoft.com/en-us/library/bb522542.aspx

SELECT *
FROM sys.trigger_event_types
ORDER BY TYPE_NAME
