-- Script: Get-TempObject.sql
-- Description: Return list of object in the tempdb database.
-- Reference: https://technet.microsoft.com/en-us/library/ms186986%28v=sql.105%29.aspx

SELECT * FROM [tempdb].[sys].[objects]