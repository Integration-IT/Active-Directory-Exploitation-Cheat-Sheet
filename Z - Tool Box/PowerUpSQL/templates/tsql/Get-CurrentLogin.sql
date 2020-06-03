-- Script: Get-CurrentLogin
-- Description: Returns the current login, and login used to login.
-- Reference: https://msdn.microsoft.com/en-us/library/ms189492.aspx
SELECT SYSTEM_USER as [CURRENT_LOGIN],ORIGINAL_LOGIN() as [ORIGINAL_LOGIN]