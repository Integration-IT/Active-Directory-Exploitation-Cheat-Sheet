
/* 
	Script: Get-SQLPolicies.sql
	Description: List the SQL Server management policies in place.
	Author: Scott Sutherland, 2017
*/

SELECT	p.policy_id,
		p.name as [PolicyName],
		p.condition_id,
		c.name as [ConditionName],
		c.facet,
		c.expression as [ConditionExpression],
		p.root_condition_id,
		p.is_enabled,
		p.date_created,
		p.date_modified,
		p.description, 
		p.created_by, 
		p.is_system,
        t.target_set_id,
        t.TYPE,
        t.type_skeleton
FROM msdb.dbo.syspolicy_policies p
INNER JOIN syspolicy_conditions c 
	ON p.condition_id = c.condition_id
INNER JOIN msdb.dbo.syspolicy_target_sets t
	ON t.object_set_id = p.object_set_id
