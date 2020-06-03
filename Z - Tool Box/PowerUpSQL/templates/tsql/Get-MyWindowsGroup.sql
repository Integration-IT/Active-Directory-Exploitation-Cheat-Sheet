-- Potentially runs nest group enumeration
-- this will show all the local and domain groups associated with the current login
-- https://www.sqlserver-dba.com/2018/05/how-to-get-the-ad-groups-of-a-login-with-syslogin_token.html
select * from sys.login_token
