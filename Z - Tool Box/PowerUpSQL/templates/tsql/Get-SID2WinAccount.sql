-- Script: Get-SID2WinAccount.sql
-- Description: Example showing how to get the domain user or group
-- for a given sid.
-- Reference: https://msdn.microsoft.com/en-us/library/ms179889.aspx

SELECT SUSER_SNAME(0x010500000000000515000000F3864381DA1516CC636051C000020000)