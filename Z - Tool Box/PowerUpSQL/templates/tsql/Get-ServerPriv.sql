-- Script: Get-ServerPriv.sql
-- Description: list all server principals with their permissions on server level.
--	This Transact-SQL script list all server principals with their permissions on 
--	server level to give a quick overview of security. For given permissions on 
--	server object like endpoints or impersonate other login it returns also the 
--	object / login etc name.Works with SQL Server 2005 and higher versions in all editions.
--	Lists only object where the executing user do have VIEW METADATA permissions for.
-- Reference: http://msdn.microsoft.com/en-us/library/ms186260.aspx
-- Note: This line below will also show full privs for sysadmin users
--       SELECT * FROM fn_my_permissions(NULL, 'SERVER');

SELECT GRE.name AS Grantee
      ,GRO.name AS Grantor
      ,PER.class_desc AS PermClass
      ,PER.permission_name AS PermName
      ,PER.state_desc AS PermState
      ,COALESCE(PRC.name, EP.name, N'') AS ObjectName
      ,COALESCE(PRC.type_desc, EP.type_desc, N'') AS ObjectType
FROM [sys].[server_permissions] AS PER
     INNER JOIN sys.server_principals AS GRO
         ON PER.grantor_principal_id = GRO.principal_id
     INNER JOIN sys.server_principals AS GRE
         ON PER.grantee_principal_id = GRE.principal_id
     LEFT JOIN sys.server_principals AS PRC
         ON PER.class = 101
            AND PER.major_id = PRC.principal_id
     LEFT JOIN sys.endpoints AS EP
         ON PER.class = 105
            AND PER.major_id = EP.endpoint_id
ORDER BY Grantee,PermName;