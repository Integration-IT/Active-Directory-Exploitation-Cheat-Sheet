-- Script: Get-AgentJob.sql
-- Description: Return a list of agent jobs.
-- Reference: https://msdn.microsoft.com/en-us/library/ms189817.aspx

SELECT 	SUSER_SNAME(owner_sid) as [JOB_OWNER], 
	job.job_id as [JOB_ID],
	name as [JOB_NAME],
	description as [JOB_DESCRIPTION],
	step_name,
	command,
	enabled,
	server,
	database_name,
	date_created
FROM [msdb].[dbo].[sysjobs] job
INNER JOIN [msdb].[dbo].[sysjobsteps] steps        
	ON job.job_id = steps.job_id
ORDER BY JOB_OWNER,JOB_NAME