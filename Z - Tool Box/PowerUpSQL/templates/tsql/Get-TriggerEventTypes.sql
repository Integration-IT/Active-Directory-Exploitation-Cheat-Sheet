-- Script: Get-TriggerEventTypes.sql
-- Requirements: Sysadmin or required SELECT privileges.
-- Description: Returns DDL event trigger types. 
-- Reference: https://msdn.microsoft.com/en-us/library/bb510452.aspx
-- Reference: https://msdn.microsoft.com/en-us/library/bb522542.aspx
-- REference: https://msdn.microsoft.com/en-us/library/bb510453.aspx

SELECT * FROM sys.trigger_event_types
