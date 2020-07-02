---------------------------------------
-- Script: writefile_bcpxpcmdshell.sql
-- Author/Modifications: Scott Sutherland
-- Based on https://www.simple-talk.com/sql/t-sql-programming/the-tsql-of-text-files/ 
-- Description:
-- Write PowerShell code to disk and run it using bcp and xp_cmdshell.
---------------------------------------

-- Enable xp_cmdshell
sp_configure 'show advanced options',1
RECONFIGURE
GO

sp_configure 'xp_cmdshell',1
RECONFIGURE
GO

-- Create variables
DECLARE @MyPowerShellCode NVARCHAR(MAX)
DECLARE @PsFileName NVARCHAR(4000)
DECLARE @TargetDirectory NVARCHAR(4000)
DECLARE @PsFilePath NVARCHAR(4000)
DECLARE @MyGlobalTempTable NVARCHAR(4000)
DECLARE @Command NVARCHAR(4000)

-- Set filename for PowerShell script
Set @PsFileName = 'MyPowerShellScript.ps1'

-- Set target directory for PowerShell script to be written to
SELECT  @TargetDirectory = REPLACE(CAST((SELECT SERVERPROPERTY('ErrorLogFileName')) as VARCHAR(MAX)),'ERRORLOG','')

-- Create full output path for creating the PowerShell script 
SELECT @PsFilePath = @TargetDirectory +  @PsFileName
SELECT @PsFilePath as PsFilePath

-- Define the PowerShell code
SET @MyPowerShellCode = 'Write-Output "hello world" | Out-File "' +  @TargetDirectory + 'intendedoutput.txt"'
SELECT @MyPowerShellCode as PsScriptCode

-- Create a global temp table with a unique name using dynamic SQL 
SELECT  @MyGlobalTempTable =  '##temp' + CONVERT(VARCHAR(12), CONVERT(INT, RAND() * 1000000))

-- Create a command to insert the PowerShell code stored in the @MyPowerShellCode variable, into the global temp table
SELECT  @Command = '
		CREATE TABLE [' + @MyGlobalTempTable + '](MyID int identity(1,1), PsCode varchar(MAX)) 
		INSERT INTO  [' + @MyGlobalTempTable + '](PsCode) 
		SELECT @MyPowerShellCode'
				
-- Execute that command 
EXECUTE sp_ExecuteSQL @command, N'@MyPowerShellCode varchar(MAX)', @MyPowerShellCode

-- Execute bcp via xp_cmdshell (as the service account) to save the contents of the temp table to MyPowerShellScript.ps1
SELECT @Command = 'bcp "SELECT PsCode from [' + @MyGlobalTempTable + ']' + '" queryout "'+ @PsFilePath + '" -c -T -S ' + @@SERVERNAME

-- Write the file
EXECUTE MASTER..xp_cmdshell @command, NO_OUTPUT

-- Drop the global temp table
EXECUTE ( 'Drop table ' + @MyGlobalTempTable )

-- Run the PowerShell script
DECLARE @runcmdps nvarchar(4000)
SET @runcmdps = 'Powershell -C "$x = gc '''+ @PsFilePath + ''';iex($X)"'
EXECUTE MASTER..xp_cmdshell @runcmdps, NO_OUTPUT

-- Delete the PowerShell script
DECLARE @runcmddel nvarchar(4000)
SET @runcmddel= 'DEL /Q "' + @PsFilePath +'"'
-- EXECUTE MASTER..xp_cmdshell @runcmddel, NO_OUTPUT
