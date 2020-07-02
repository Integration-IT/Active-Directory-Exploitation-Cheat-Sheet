#ifndef  SERVICES_H
#define  SERVICES_H

#pragma comment(lib, "Advapi32.lib")

// Fichiers d'en-tête Windows :
#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <tchar.h>
#include <Strsafe.h>

#define		SERVICE_NAME			L"BEROOT"

VOID DeleteSvc();
VOID ServiceMain(int argc, char **argv);
BOOL StartSampleService(WCHAR* serviceName);

#endif // SERVICES_H