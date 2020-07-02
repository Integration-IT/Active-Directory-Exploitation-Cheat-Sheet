-- Note: Requires the driver to be installed ahead of time.
-- EXEC sp_MSset_oledb_prop N'Microsoft.ACE.OLEDB.12.0', N'AllowInProcess', 1  -- not required
-- EXEC sp_MSset_oledb_prop N'Microsoft.ACE.OLEDB.12.0', N'DynamicParameters', 1  -- not required
-- EXEC master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines','SandBoxMode','REG_DWORD',1; -- not required

-- list available providers
EXEC sp_MSset_oledb_prop -- get available providers

-- Enable show advanced options
sp_configure 'show advanced options',1
reconfigure
go

-- Enable ad hoc queries
sp_configure 'ad hoc distributed queries',1
reconfigure
go

-- Read text file
SELECT * FROM OPENROWSET('Microsoft.ACE.OLEDB.12.0','Text;Database=c:\temp\;HDR=Yes;FORMAT=text', 'SELECT * FROM [file.txt]')

-- Note: This also works with unc paths \\ip\file.txt
-- Note: This also works with webdav paths \\ip@80\file.txt However, the target web server needs to support propfind.
