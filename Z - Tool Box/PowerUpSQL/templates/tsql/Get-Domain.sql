-- Script: Get-Domain.sql
-- Description: Returns the default domain of the SQL Server.
-- Reference: http://www.sanssql.com/2008/11/find-domain-name-using-t-sql.html

SELECT DEFAULT_DOMAIN() as [DEFAULT_DOMAIN]