# RottenPotatoNG
New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.

## RottenPotatoDLL
This project generates a DLL and EXE file. The DLL contains all the code necessary to perform the RottenPotato attack and get a handle to a privileged token. The MSFRottenPotatoTestHarness project simply shows example usage for the DLL. For more examples, see https://github.com/hatRiot/token-priv/tree/master/poptoke/poptoke, specifically the SeAssignPrimaryTokenPrivilege.cpp and SeImpersonatePrivilege.cpp files. 

## RottenPotatoEXE
This project is identical to the above, except the code is all wrapped into a single project/binary. This may be more useful for some penetration testing scenarios.

Modify the "main" method in MSFRottenPotato.cpp to change what command will be run. By default it just runs cmd.exe to pop a command shell.
