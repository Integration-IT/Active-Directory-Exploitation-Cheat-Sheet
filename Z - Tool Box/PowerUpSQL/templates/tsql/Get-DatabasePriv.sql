-- Script: Get-DatabasePriv.sql
-- Description: This script will return all of the database user
--	privileges for the current database.
-- Reference: http://msdn.microsoft.com/en-us/library/ms188367.aspx
-- Note: This line below will also show full privs for sysadmin users
--       SELECT * FROM fn_my_permissions(NULL, 'DATABASE'); 
-- http://stackoverflow.com/questions/410396/public-role-access-in-sql-server

SELECT DISTINCT rp.name, 
                ObjectType = rp.type_desc, 
                PermissionType = pm.class_desc, 
                pm.permission_name, 
                pm.state_desc, 
                ObjectType = CASE 
                               WHEN obj.type_desc IS NULL 
                                     OR obj.type_desc = 'SYSTEM_TABLE' THEN 
                               pm.class_desc 
                               ELSE obj.type_desc 
                             END, 
                [ObjectName] = Isnull(ss.name, Object_name(pm.major_id)) 
FROM   sys.database_principals rp 
       INNER JOIN sys.database_permissions pm 
               ON pm.grantee_principal_id = rp.principal_id 
       LEFT JOIN sys.schemas ss 
              ON pm.major_id = ss.schema_id 
       LEFT JOIN sys.objects obj 
              ON pm.[major_id] = obj.[object_id] 
