# SeBackupPrivilege

On Windows, if a user has the "[Back up files and directories](http://technet.microsoft.com/en-us/library/cc787956.aspx)" right, he gets assigned the `SE_BACKUP_NAME`/`SeBackupPrivilege` [privilege](http://msdn.microsoft.com/en-us/library/windows/desktop/bb530716.aspx). Such privilege is disabled by default but when switched on it allows the user to access directories/files _that he doesn't own_ or _doesn't have permission to_. In MSDN's own words:

> This user right determines which users can bypass file and directory,
> registry, and other persistent object permissions for the purposes of
> backing up the system.

In order to exploit `SeBackupPrivilege` you have to:

- Enable the privilege.  
  This alone lets you traverse (`cd` into) any<sup>1</sup> directory, local or remote, and list (`dir`, `Get-ChildItem`) its contents.
- If you want to read/copy data out of a "normally forbidden" folder, you have to act as a backup software.
  The shell `copy` command won't work; you'll need to open the source file manually using `CreateFile` making sure to specify the `FILE_FLAG_BACKUP_SEMANTICS` flag.

This library exposes three PowerShell CmdLets that do just that.

## Example usage

```
PS C:\scripts> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\scripts> Import-Module .\SeBackupPrivilegeCmdLets.dll
PS C:\scripts> Get-SeBackupPrivilege # ...or whoami /priv | findstr Backup
SeBackupPrivilege is disabled
PS C:\scripts> dir E:\V_BASE
Get-ChildItem : Access to the path 'E:\V_BASE' is denied.
At line:1 char:4
+ dir <<<<  E:\V_BASE
    + CategoryInfo          : PermissionDenied: (E:\V_BASE:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

PS C:\scripts> Set-SeBackupPrivilege
PS C:\scripts> Get-SeBackupPrivilege
SeBackupPrivilege is enabled
PS C:\scripts> dir E:\V_BASE # ...having enabled the privilege, this now works


    Directory: E:\V_BASE


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----        18/07/2013     13:04            Private

PS C:\scripts> cd E:\V_BASE\Private
PS E:\V_BASE\Private> dir


    Directory: E:\V_BASE\Private


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-----        05/07/2013     12:29     306435 report.pdf

PS E:\V_BASE\Private> Copy-FileSeBackupPrivilege .\report.pdf c:\temp\x.pdf -Overwrite
Copied 306435 bytes

PS E:\V_BASE\Private>
```

## Building/misc

The following dlls are compiled for x64, .NET Framework 2.0 . If they don't match your environment, you'll have to build your own; just import the project into [SharpDevelop](http://www.icsharpcode.net/opensource/sd/) and you should be good to go.

- [SeBackupPrivilegeUtils.dll](https://github.com/giuliano108/SeBackupPrivilege/blob/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll?raw=true)
- [SeBackupPrivilegeCmdLets.dll](https://github.com/giuliano108/SeBackupPrivilege/blob/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll?raw=true)

These resources have been extremely helpful when putting this stuff together:

- Stack Overflow: [How to detect if "Debug Programs" Windows privilege is set?](http://stackoverflow.com/questions/4880197/how-to-detect-if-debug-programs-windows-privilege-is-set)
- Stack Overflow: [Setting size of TOKEN_PRIVILEGES.LUID_AND_ATTRIBUTES array returned by GetTokenInformation](http://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni)
- [Adjusting Token Privileges in PowerShell](http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/)
- [PInvoke.net](http://www.pinvoke.net/)

- - -

[1] Explicit denies should still block you, though...
