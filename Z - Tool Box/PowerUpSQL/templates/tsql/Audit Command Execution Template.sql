/*
	Script Name: Audit Command Execution Template.sql
	Description: This TSQL script can be used to configure SQL Server to log events commonly associated with operating system command execution to the Windows Application log.
	Author: Scott Sutherland (@_nullbind), 2017 NetSPI 
	
	SIEM Cheatsheet for Potentially Malicious Events in SQL Server

	Windows Application Log
	Event ID: 15457
	Description: This event is associated with server configuration changes.  Watch for the following configuration changes:

	Configuration option 'external scripts enabled' changed from 0 to 1. Run the RECONFIGURE statement to install.
	Configuration option 'Ole Automation Procedures' changed from 0 to 1. Run the RECONFIGURE statement to install.
	Configuration option 'clr enabled' changed from 0 to 1. Run the RECONFIGURE statement to install.
	Configuration option 'clr strict security' changed from 0 to 1. Run the RECONFIGURE statement to install.
	Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
	Configuration option 'Ad Hoc Distributed Queries' changed from 0 to 1. Run the RECONFIGURE statement to install.

	Windows Application Log
	Event ID: 33205
	Description: This event applies to the SQL Server Agent and database level changes. Watch for the following:

	msdb.dbo.sp_add_job Watch for potentially malicious ActiveX, cmdexec, and powershell jobs.
	"sp_execute_external_script" Watch for cmd.exe and similar calls. 
	"sp_OACreate" Watch for Sp_oacreate 'wscript.shell’ and similar calls
	"sp_addextendedproc" Watch for any usage
	"sp_add_trusted_assembly" Watch for unauthorized usage
	
	NOTE: Make sure to enabled the auditing as shown below.
*/


/*
	Create and Enable Audit Policies
*/
USE master 
CREATE SERVER AUDIT DerbyconAudit
TO APPLICATION_LOG 
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE) 
ALTER SERVER AUDIT DerbyconAudit
WITH (STATE = ON)

-- Server: Audit server configuration changes
-- Windows Log: Application
-- Events: 15457 
CREATE SERVER AUDIT SPECIFICATION [Audit_Server_Configuration_Changes]
FOR SERVER AUDIT DerbyconAudit
ADD (AUDIT_CHANGE_GROUP), 								-- Audit Audit changes
ADD (SERVER_OPERATION_GROUP)  								-- Audit server changes
WITH (STATE = ON)

-- DATABASE: Audit common agent job activity
-- Windows Log: Application
-- Events: 33205 
Use msdb
CREATE DATABASE AUDIT SPECIFICATION [Audit_Agent_Jobs]
FOR SERVER AUDIT [DerbyconAudit]
ADD (EXECUTE ON OBJECT::[dbo].[sp_add_job] BY [dbo])
WITH (STATE = ON)

-- DATABASE: Audit potentially dangerous procedures
-- Windows Log: Application
-- Events: 33205 
use master
CREATE DATABASE AUDIT SPECIFICATION [Audit_OSCMDEXEC]
FOR SERVER AUDIT [DerbyconAudit]
ADD (EXECUTE ON OBJECT::[dbo].[xp_cmdshell] BY [dbo]),					-- Audit xp_cmdshell execution
ADD (EXECUTE ON OBJECT::[dbo].[sp_addextendedproc] BY [dbo]),				-- Audit additional of custom extended stored procedures
ADD (EXECUTE ON OBJECT::[dbo].[sp_execute_external_script] BY [dbo]), 			-- Audit execution of external scripts such as R and Python
ADD (EXECUTE ON OBJECT::[dbo].[Sp_oacreate] BY [dbo])					-- Audit OLE Automation Procedure execution
WITH (STATE = ON)


/*
	View Audit Policies
*/

-- View audits
SELECT * FROM sys.dm_server_audit_status

-- View server specifications
SELECT audit_id, 
a.name as audit_name, 
s.name as server_specification_name, 
d.audit_action_name, 
s.is_state_enabled, 
d.is_group, 
d.audit_action_id, 
s.create_date, 
s.modify_date 
FROM sys.server_audits AS a 
JOIN sys.server_audit_specifications AS s 
ON a.audit_guid = s.audit_guid 
JOIN sys.server_audit_specification_details AS d 
ON s.server_specification_id = d.server_specification_id 

-- View database specifications
SELECT a.audit_id, 
a.name as audit_name, 
s.name as database_specification_name, 
d.audit_action_name, 
d.major_id,
OBJECT_NAME(d.major_id) as object,
s.is_state_enabled, 
d.is_group, s.create_date, 
s.modify_date, 
d.audited_result 
FROM sys.server_audits AS a 
JOIN sys.database_audit_specifications AS s 
ON a.audit_guid = s.audit_guid 
JOIN sys.database_audit_specification_details AS d 
ON s.database_specification_id = d.database_specification_id 


/*
	Remove Audit Policies
*/

-- Remove Audit_Server_Configuration_Changes
use master
ALTER SERVER AUDIT SPECIFICATION [Audit_Server_Configuration_Changes]
WITH (STATE = OFF)
DROP SERVER AUDIT SPECIFICATION [Audit_Server_Configuration_Changes]

-- Remove Audit_OSCMDEXEC
USE master
ALTER DATABASE AUDIT SPECIFICATION [Audit_OSCMDEXEC]
WITH (STATE = OFF)
DROP DATABASE AUDIT SPECIFICATION [Audit_OSCMDEXEC]

-- Remove Audit_Agent_Jobs
USE msdb
ALTER DATABASE AUDIT SPECIFICATION [Audit_Agent_Jobs]
WITH (STATE = OFF)
DROP DATABASE AUDIT SPECIFICATION [Audit_Agent_Jobs]

-- Remove DerbyconAudit audit
ALTER SERVER AUDIT DerbyconAudit
WITH (STATE = OFF)
DROP SERVER AUDIT DerbyconAudit
