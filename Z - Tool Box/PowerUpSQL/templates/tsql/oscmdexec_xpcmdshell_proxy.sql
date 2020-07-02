-- Summary
-- Create a SQL Server login that maps to a database user/role 
-- that has been given explicit privs to execute xp_cmdshell 
-- once the xp_proxy_account has been configured with valid windows credentials
-- ooook then

USE MASTER;
GO

-- enable xp_cmdshell on the server
sp_configure 'show advanced options',1
reconfigure
go

sp_configure 'xp_cmdshell',1
reconfigure
go

-- Create login from windows user
CREATE LOGIN [SQLServer1\User1] FROM WINDOWS;

-- Create xp_cmdshell_proxy
EXEC sp_xp_cmdshell_proxy_account 'SQLServer1\User1', 'Password!'; 

-- Create database role 
CREATE ROLE [CmdShell_Executor] AUTHORIZATION [dbo]

-- Grant role privs to execute xp_cmdshell using proxy
GRANT EXEC ON xp_cmdshell TO [CmdShell_Executor]

-- Create a database user 
CREATE USER [user1] FROM LOGIN [user1];

-- Add database user to the role 
EXEC sp_addrolemember [CmdShell_Executor],[user1];

-- Grant user1 database user privs to execute xp_cmdshell using proxy directly
GRANT EXEC ON xp_cmdshell TO [user1]


-- Login as user1 - will show SQLServere1\User1 instead of service account
xp_cmdshell 'whoami'
