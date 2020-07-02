
-- Re install
sp_addextendedproc 'xp_cmdshell', 'xplog70.dll'


-- re enable
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO

EXEC sp_configure 'xp_cmdshell', 1; 
RECONFIGURE;
GO


-- run
Exec master..xp_cmdshell 'whoami'
