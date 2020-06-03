// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

//typedef int(__stdcall *msgbox)(HWND, LPCSTR, LPCSTR, UINT);
typedef int(__stdcall *winexec)(LPCSTR, UINT);

/*BOOL messagebox(char* message)
{
	HMODULE hMod = LoadLibrary(L"User32.dll");
	msgbox f = NULL;

	if (hMod != NULL) {
		f = reinterpret_cast<msgbox>(GetProcAddress(hMod, "MessageBoxA"));
	}

	if (f != NULL) {
		(*f)(NULL, message, "Hello", MB_OK);
	}

	if (hMod != NULL) {
		FreeLibrary(hMod);
		return TRUE;
	}
	return FALSE;
}*/
 
BOOL exectute_command()
{
	HMODULE hMod = LoadLibrary(L"Kernel32.dll");
	winexec f = NULL;

	if (hMod != NULL) {
		f = reinterpret_cast<winexec>(GetProcAddress(hMod, "WinExec"));
	}

	if (f != NULL) {
		(*f)("powershell.exe /c test.bat", 0);
	}

	if (hMod != NULL) {
		FreeLibrary(hMod);
		return TRUE;
	}
	return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		exectute_command();
		//messagebox("Hello from dll");
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

