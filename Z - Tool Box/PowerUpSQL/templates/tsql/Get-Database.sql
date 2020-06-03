-- Script: Get-Database.sql
-- Description: This will return viewable databases and some associated meta data.
--	Filename may not be returned if the current user is not a sysadmin.
--	If the "VIEW ANY DATABASE" privilege has been revoked from Public
--	then some databases may not be listed if the current user is not a sysadmin.
-- Reference: https://msdn.microsoft.com/en-us/library/ms178534.aspx
-- TODO: Fix is_encrypted column - should only show on versions =>10

SELECT      	@@SERVERNAME as [Instance],
            	a.database_id as [DatabaseId],
            	a.name as [DatabaseName],
            	SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
		IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
		a.is_trustworthy_on,
		a.is_db_chaining_on,
		a.is_broker_enabled,
           	a.is_encrypted,
           	a.is_read_only,
		a.create_date,
            	a.recovery_model_desc,
            	b.filename as [FileName],
            	(SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2)) from sys.master_files where name like a.name) as [DbSizeMb],
            	HAS_DBACCESS(a.name) as [has_dbaccess]
FROM		[sys].[databases] a
INNER JOIN	[sys].[sysdatabases] b 
ON		a.database_id = b.dbid 
