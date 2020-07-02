-- Script: Get-ProcSignedByCertLogin.sql
-- Description: Return a list of procedures signed with a certificate 
-- for the current database that also have logins that were generated from them.
-- Reference: https://books.google.com/books?id=lTtQXn2pO5kC&pg=PA158&dq=cp.thumbprint+%3D+cer.thumbprint+AND&hl=en&sa=X&ei=ID1tVeioDZCpogSO4oCgCA&ved=0CCcQ6AEwAA#v=onepage&q=cp.thumbprint%20%3D%20cer.thumbprint%20AND&f=false

SELECT spr.ROUTINE_CATALOG as [DATABASE_NAME],
	spr.SPECIFIC_SCHEMA as [SCHEMA_NAME],
	spr.ROUTINE_NAME as [SP_NAME],
	spr.ROUTINE_DEFINITION as SP_CODE,
	CASE cp.crypt_type
		when 'SPVC' then cer.name
		when 'CPVC' then Cer.name
		when 'SPVA' then ak.name
		when 'CPVA' then ak.name
	END as CERT_NAME,
	sp.name as CERT_LOGIN,
	sp.sid as CERT_SID
FROM [sys].[crypt_properties] cp
INNER JOIN [sys].[objects] o ON cp.major_id = o.object_id
LEFT JOIN [sys].[certificates] cer 
	ON cp.thumbprint = cer.thumbprint
LEFT JOIN [sys].[asymmetric_keys] ak 
	ON cp.thumbprint = ak.thumbprint
LEFT JOIN [INFORMATION_SCHEMA].[ROUTINES] spr 
	ON spr.ROUTINE_NAME = o.name
LEFT JOIN [sys].[server_principals] sp
	ON sp.sid = cer.sid
WHERE o.type_desc = 'SQL_STORED_PROCEDURE'
	AND sp.name is NOT NULL
ORDER BY CERT_NAME