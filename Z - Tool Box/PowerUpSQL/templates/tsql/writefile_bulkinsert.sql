-- author: antti rantassari, 2017
-- Description: Copy file contents to another file via local, unc, or webdav path
-- summary = file contains varchar data, field is an int, throws casting error on read, set error output to file, tada!
-- requires sysadmin or bulk insert privs

create table #errortable (ignore int)

bulk insert #errortable
from '\\localhost\c$\windows\win.ini' -- or  'c:\windows\system32\win.ni' -- or \\hostanme@SSL\folder\file.ini' 
with
(
fieldterminator=',',
rowterminator='\n',
errorfile='c:\windows\temp\thatjusthappend.txt'
)

drop table #errortable
