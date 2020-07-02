-- Note: Requires the driver to be installed ahead of time.

-- Enable show advanced options
sp_configure 'show advanced options',1
reconfigure
go

-- Enable ad hoc queries
sp_configure 'ad hoc distributed queries',1
reconfigure
go

-- list available providers
EXEC sp_MSset_oledb_prop

-- Read a text file
SELECT * FROM OpenDataSource( 'Microsoft.ACE.OLEDB.12.0','Data Source="c:\temp";Extended properties="Text;hdr=no"')...file#txt

-- Note: This also works with unc paths \\ip\file.txt
-- Note: This also works with webdav paths \\ip@80\file.txt However, the target web server needs to support propfind.
