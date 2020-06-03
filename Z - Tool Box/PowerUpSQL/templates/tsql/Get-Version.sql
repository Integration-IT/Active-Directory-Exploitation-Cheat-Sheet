-- Description: Return SQL Server and OS version information.
-- Reference: https://msdn.microsoft.com/en-us/library/ms174396.aspx

-- Get machine type
DECLARE @MachineType  SYSNAME
EXECUTE master.dbo.xp_regread
@rootkey		= N'HKEY_LOCAL_MACHINE',
@key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
@value_name		= N'ProductType', 
@value			= @MachineType output

-- Get listening port
Declare @PortNumber varchar(20) 
EXECUTE master..xp_regread 
@rootkey		= 'HKEY_LOCAL_MACHINE', 
@key			= 'SOFTWARE\MICROSOFT\MSSQLServer\MSSQLServer\Supersocketnetlib\TCP',
@value_name		= 'Tcpport',
@value			= @PortNumber OUTPUT

-- Return server and version information
SELECT @@servername AS [SERVER_INSTANCE],
	@PortNumber AS [TCP_PORT],
	DEFAULT_DOMAIN() AS [DEFAULT_DOMAIN],
	SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) AS [MAJOR_VERSION],
	serverproperty('Edition') AS [VERSION_EDITION],
	SERVERPROPERTY('ProductLevel') AS [PRODUCT_LEVEL],
	SERVERPROPERTY('productversion') AS [VERSION_NUMBER],
	SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) AS [ARCHITECTURE],
	@MachineType as [OS_MACHINE_TYPE],
	RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) AS [OS_VERSION_NUMBER]