-- Script: Get-ServerCertLogin.sql
-- Description: Return a list of server logins created from a certificate.
-- Reference: https://msdn.microsoft.com/en-us/library/ms188786.aspx

SELECT * 
FROM [sys].[server_principals] 
WHERE type = 'C'
 