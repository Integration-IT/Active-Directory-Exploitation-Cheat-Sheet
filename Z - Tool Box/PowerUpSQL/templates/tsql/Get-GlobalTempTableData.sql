-- Script: Get-GlobalTempTableData.sql
-- Author: Scott Sutherland
-- Description: Monitor for global temp tables.  
-- Sometimes they're used to store sensitive data 
-- or code that may be executed in another user's context.

------------------------------------------
-- List All Global Temp Tables
------------------------------------------

SELECT name FROM tempdb.sys.tables WHERE name LIKE '##%'

------------------------------------------
-- View Contents of All Global Temp Tables
------------------------------------------

-- Setup variables
DECLARE @mytempname varchar(max)
DECLARE @psmyscript varchar(max)

-- Iterate through all global temp tables 
DECLARE MY_CURSOR CURSOR 
	FOR SELECT name FROM tempdb.sys.tables WHERE name LIKE '##%'
OPEN MY_CURSOR
FETCH NEXT FROM MY_CURSOR INTO @mytempname 
WHILE @@FETCH_STATUS = 0
BEGIN 

	-- Print table name
    PRINT @mytempname 
	
	-- Select table contents
	DECLARE @myname varchar(max)
	SET @myname = 'SELECT * FROM [' + @mytempname + ']'
	EXEC(@myname)
	
	-- Next 
	FETCH NEXT FROM MY_CURSOR INTO @mytempname 
END
CLOSE MY_CURSOR
DEALLOCATE MY_CURSOR

------------------------------------------
-- Monitor content of All Global Temp Tables 
-- in a Loop
-- Note: Make sure to manage this one
-- carefully so you dont start the server 
-- on fire. :)
------------------------------------------

While 1=1
BEGIN
	-- Add delay if required
	-- waitfor delay '0:0:2'
	
	-- Setup variables
	DECLARE @mytempname varchar(max)
	DECLARE @psmyscript varchar(max)

	-- Iterate through all global temp tables 
	DECLARE MY_CURSOR CURSOR 
		FOR SELECT name FROM tempdb.sys.tables WHERE name LIKE '##%'
	OPEN MY_CURSOR
	FETCH NEXT FROM MY_CURSOR INTO @mytempname 
	WHILE @@FETCH_STATUS = 0
	BEGIN 

		-- Print table name
	    PRINT @mytempname 

		-- Select table contents
		DECLARE @myname varchar(max)
		SET @myname = 'SELECT * FROM [' + @mytempname + ']'
		EXEC(@myname)

		-- Next record
		FETCH NEXT FROM MY_CURSOR INTO @mytempname 
	END
	CLOSE MY_CURSOR
	DEALLOCATE MY_CURSOR
END

