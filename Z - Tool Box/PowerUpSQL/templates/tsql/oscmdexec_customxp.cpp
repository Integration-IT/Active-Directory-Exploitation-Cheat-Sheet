# Register xp via local path: sp_addextendedproc 'RunPs', 'c:\myxp.dll'
# Register xp via UNC path: sp_addextendedproc 'RunPs', '\\servername\pathtofile\myxp.dll'
# Run: exec RunPs
# Unregister xp: sp_dropextendedproc 'RunPs'


#include "stdio.h" 
#include "stdafx.h" 
#include "srv.h" 
#include "shellapi.h" 
#include "string" 

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call)
{ 	
	case DLL_PROCESS_ATTACH: 
	case DLL_THREAD_ATTACH: 
	case DLL_THREAD_DETACH: 
	case DLL_PROCESS_DETACH: 
	break; 
}

return 1;
 }

 __declspec(dllexport) ULONG __GetXpVersion() { 
return 1; 
} 

#define RUNCMD_FUNC extern "C" __declspec (dllexport) 
RUNPS_FUNC int __stdcall RunPs(const char * Command) { 
ShellExecute(NULL, TEXT("open"), TEXT("powershell"), TEXT(" -C \" 'This is a test.'|out-file c:\\temp\\test_ps2.txt \" "), TEXT(" C:\\ "), SW_SHOW); 
system("PowerShell -C \"'This is a test.'|out-file c:\\temp\\test_ps1.txt\""); 
return 1;
}
