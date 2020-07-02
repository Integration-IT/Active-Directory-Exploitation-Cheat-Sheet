-- Script: Get-WinAccount2SID.sql
-- Description: Example showing how to get the SID of
--	of a supplied domain user or group. Note that the SID is hex encoded.
-- Reference: https://msdn.microsoft.com/en-us/library/ms179889.aspx

DECLARE @DOMAIN_ADMINISTRATOR varchar(100)
DECLARE @CMD varchar(100)
SET @DOMAIN_ADMINISTRATOR = default_domain() + '\Domain Admins'
SET @CMD = 'select SUSER_SID(''' + @DOMAIN_ADMINISTRATOR + ''')'
EXEC(@CMD)
