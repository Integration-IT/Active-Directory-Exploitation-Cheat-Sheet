-- Script: Get-ProcSigned.sql
-- Description: Return a list of signed stored procedures
-- for the current database.
-- Reference: https://books.google.com/books?id=lTtQXn2pO5kC&pg=PA158&dq=cp.thumbprint+%3D+cer.thumbprint+AND&hl=en&sa=X&ei=ID1tVeioDZCpogSO4oCgCA&ved=0CCcQ6AEwAA#v=onepage&q=cp.thumbprint%20%3D%20cer.thumbprint%20AND&f=false

SELECT o.name as ObjectName,
	o.type_desc as ObjectType,
	cp.crypt_type as CryptType,
	CASE cp.crypt_type
		when 'SPVC' then cer.name
		when 'CPVC' then Cer.name
		when 'SPVA' then ak.name
		when 'CPVA' then ak.name
	END as keyname
FROM sys.crypt_properties cp
JOIN sys.objects  o ON cp.major_id =  o.object_id
LEFT JOIN  sys.certificates cer 
	ON cp.thumbprint = cer.thumbprint 
	AND cp.crypt_type IN ('SPVC','CPVC')
LEFT JOIN  sys.asymmetric_keys ak 
	ON cp.thumbprint = ak.thumbprint 
	AND cp.crypt_type IN ('SPVA','CPVA') 
ORDER BY keyname,ObjectType,ObjectName