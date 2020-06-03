-- Option 1 - local file
-- Create temp table
CREATE TABLE #file (content nvarchar(4000));

-- Read file into temp table
BULK INSERT #file FROM 'c:\temp\file.txt';

-- Select contents of file
SELECT content FROM #file

-- Option 2 - file via unc path
-- Create temp table
CREATE TABLE #file (content nvarchar(4000));

-- Read file into temp table
BULK INSERT #file FROM '\\127.0.0.1\c$\temp\file.txt';

-- Select contents of file
SELECT content FROM #file

-- Drop temp table
DROP TABLE #file

-- Option 3 - file via webdav path
-- Create temp table
CREATE TABLE #file (content nvarchar(4000));

-- Read file into temp table
BULK INSERT #file FROM '\\sharepoint.acme.com@SSL\Path\to\file.txt';

-- Select contents of file
SELECT content FROM #file

-- Drop temp table
DROP TABLE #file
