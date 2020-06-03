-- select the contents of a file using openrowset
-- note: ad-hoc queries have to be enabled
-- https://docs.microsoft.com/en-us/sql/t-sql/functions/openrowset-transact-sql

-- Enable show advanced options
sp_configure 'show advanced options',1
reconfigure
go

-- Enable ad hoc queries
sp_configure 'ad hoc distributed queries',1
reconfigure
go

-- Read text file
SELECT cast(BulkColumn as varchar(max)) as Document FROM OPENROWSET(BULK N'C:\windows\temp\blah.txt', SINGLE_BLOB) AS Document

-- Note: This also works with unc paths \\ip\file.txt
-- Note: This also works with webdav paths \\ip@80\file.txt However, the target web server needs to support propfind.
