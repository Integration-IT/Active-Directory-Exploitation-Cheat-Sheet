
-- Script: Get-SQLDomainUser-Example.sql
-- Description: Use OLE DB ADSI connections to grab a list of domain users via SQL Server links (OpenQuery) and adhoc queries (OpenRowSet).
-- Author: Scott Sutherland, NetSPI 2017


--------------------------------------
-- Create SQL Server link to ADSI
--------------------------------------
IF (SELECT count(*) FROM master..sysservers WHERE srvname = 'ADSI') = 0
	EXEC master.dbo.sp_addlinkedserver @server = N'ADSI', 
	@srvproduct=N'Active Directory Service Interfaces', 
	@provider=N'ADSDSOObject', 
	@datasrc=N'adsdatasource'
ELSE
	SELECT 'The target SQL Server link already exists.'	
GO

-- Verify the link was created 
SELECT * FROM master..sysservers WHERE providername = 'ADSDSOObject'

-- Configure ADSI link to Authenticate as current user
EXEC sp_addlinkedsrvlogin 
	@rmtsrvname=N'ADSI',
	@useself=N'True',
	@locallogin=NULL,
	@rmtuser=NULL,
	@rmtpassword=NULL
GO


--------------------------------------
-- Create SQL Server link to ADSI2
--------------------------------------
IF (SELECT count(*) FROM master..sysservers WHERE srvname = 'ADSI2') = 0
	EXEC master.dbo.sp_addlinkedserver @server = N'ADSI2', 
	@srvproduct=N'Active Directory Service Interfaces', 
	@provider=N'ADSDSOObject', 
	@datasrc=N'adsdatasource'
ELSE
	SELECT 'The target SQL Server link already exists.'
	-- EXEC master.dbo.sp_dropserver @server=N'ADSI', @droplogins='droplogins'
	
GO

-- Verify the link was created 
SELECT * FROM master..sysservers WHERE providername = 'ADSDSOObject'

-- Configure the ADSI2 link to Authenticate as provided domain user
EXEC sp_addlinkedsrvlogin 
@rmtsrvname=N'ADSI2',
@useself=N'False',
@locallogin=NULL,
@rmtuser=N'Domain\User',
@rmtpassword=N'Password123!'
GO


--------------------------------------
-- Run basic LDAP queries - OpenQuery
--------------------------------------

-- sa as current failed, but sysadmin domain user works
SELECT * FROM OpenQuery(ADSI,'<LDAP://domain>;(&(objectCategory=Person)(objectClass=user));samaccountname,name,admincount,whencreated,whenchanged,adspath;subtree')

-- provided domain user works
SELECT * FROM OpenQuery(ADSI2,'<LDAP://domain>;(&(objectCategory=Person)(objectClass=user));samaccountname,name,admincount,whencreated,whenchanged,adspath;subtree')

-- sa as current failed, but sysadmin domain user works
SELECT * FROM OpenQuery(ADSI, 'SELECT samaccountname,name,admincount,whencreated,whenchanged,adspath FROM  ''LDAP://domain'' WHERE objectClass =  ''User'' ') AS tblADSI

-- provided domain user works
SELECT * FROM OpenQuery(ADSI2, 'SELECT samaccountname,name,admincount,whencreated,whenchanged,adspath FROM  ''LDAP://domain'' WHERE objectClass =  ''User'' ') AS tblADSI


--------------------------------------
-- Remove links and login mappings
--------------------------------------
EXEC master.dbo.sp_dropserver @server=N'ADSI', @droplogins='droplogins'
EXEC master.dbo.sp_dropserver @server=N'ADSI2', @droplogins='droplogins'


--------------------------------------
-- Enabled adhoc queries on the server
--------------------------------------
EXEC master.sys.sp_configure 'Show Advanced Options',1
reconfigure
go

EXEC master.sys.sp_configure 'Ad Hoc Distributed Queries',1
reconfigure
go


--------------------------------------
-- Run basic LDAP queries - OpenRowSet
--------------------------------------
-- Need to confirm which scenario run as service account.

-- Run without credential in syntax option 1 - works as sa
SELECT *
FROM OPENROWSET('ADSDSOOBJECT','adsdatasource','SELECT samaccountname,name,admincount,whencreated,whenchanged,adspath
FROM ''LDAP://domain''
WHERE objectClass =  ''User'' ')

-- Run with credential in syntax option 1 - works as sa
SELECT *
FROM OPENROWSET('ADSDSOOBJECT','User ID=domain\user; Password=Password123!;','SELECT samaccountname,name,admincount,whencreated,whenchanged,adspath
FROM ''LDAP://domain''
WHERE objectClass =  ''User'' ')

-- Run with credential in synatx option 2 - works as sa login
SELECT * 
FROM OPENROWSET('ADSDSOOBJECT','User ID=domain\user; Password=Password123!;',
'<LDAP://domain>;(&(objectCategory=Person)(objectClass=user));samaccountname,name,admincount,whencreated,whenchanged,adspath;subtree')
