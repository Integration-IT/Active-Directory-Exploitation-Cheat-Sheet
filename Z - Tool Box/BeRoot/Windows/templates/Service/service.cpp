#include "service.h"

// ############################## Start Service ##############################

BOOL StartSampleService(WCHAR* serviceName)
{
	SC_HANDLE schService;
	SERVICE_STATUS ssStatus;
	DWORD dwOldCheckPoint;
	DWORD dwStartTickCount;
	DWORD dwWaitTime;

	SC_HANDLE schSCManager;
	// Open a handle to the SC Manager database...
	schSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	LPCTSTR lpszServiceName = serviceName;
	schService = OpenServiceW(schSCManager, serviceName, SERVICE_ALL_ACCESS);
	if (schService == NULL)
		return 1;

	// Proceed to other task...
	if (!StartServiceW(schService, 0, NULL))
		return 1;

	// Check the status until the service is no longer start pending.
	if (!QueryServiceStatus(schService, &ssStatus))
		return 1;

	// Save the tick count and initial checkpoint.
	dwStartTickCount = GetTickCount();
	dwOldCheckPoint = ssStatus.dwCheckPoint;
	while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is
		// one tenth the wait hint, but no less than 1 second and no
		// more than 10 seconds...
		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;

		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status again...
		if (!QueryServiceStatus(schService, &ssStatus))
			break;

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// The service is making progress...
			dwStartTickCount = GetTickCount();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			// No progress made within the wait hint => Failed
			if ((GetTickCount() - dwStartTickCount) > ssStatus.dwWaitHint)
				break;
		}
	}

	if (CloseServiceHandle(schService) == 0)
		return 1;

	if (ssStatus.dwCurrentState == SERVICE_RUNNING)
		return 0;

	return 1;
}

// ############################## Service functions ##############################

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hServiceStatus;

// Control handler function callback
void ControlHandler(DWORD request)
{
	switch (request) {
	case SERVICE_CONTROL_STOP:
		// Service has been stopped
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hServiceStatus, &ServiceStatus);
		return;

	case SERVICE_CONTROL_SHUTDOWN:
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(hServiceStatus, &ServiceStatus);
		return;

	default:
		break;
	}
	// Report current status
	SetServiceStatus(hServiceStatus, &ServiceStatus);
}

void StopService(WCHAR* serviceName){
	// Open service manager
	SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
		return;

	// Open service
	SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
	if (hService == NULL)
	{
		CloseServiceHandle(hSCM);
		return;
	}

	// Stop the service
	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	SetServiceStatus(hServiceStatus, &ServiceStatus);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCM);
}

// Delete Service
VOID DeleteSvc()
{
	SC_HANDLE	schSCManager;
	SC_HANDLE	schService;
	WCHAR*		serviceName = NULL;

	serviceName = SERVICE_NAME;
	if (serviceName == NULL) return;

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		//DebugPrintf(L"OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,       // SCM database 
		serviceName,          // name of service 
		DELETE);            // need delete access 

	if (schService == NULL)
	{
		//DebugPrintf(L"OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}

	// Delete the service.
	DeleteService(schService);
	/*if (!DeleteService(schService))
		DebugPrintf(L"DeleteService failed (%d)\n", GetLastError());
	else
		DebugPrintf(L"Service deleted successfully");
	*/

	free(serviceName);
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

// Service main function callback
VOID ServiceMain(int argc, char **argv)
{
	DWORD status = 0;
	DWORD specificError = 0;
	WCHAR* serviceName = NULL;

	serviceName = SERVICE_NAME;
	if (serviceName == NULL) return;
	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hServiceStatus = RegisterServiceCtrlHandlerW(serviceName, (LPHANDLER_FUNCTION)ControlHandler);
	if (hServiceStatus == (SERVICE_STATUS_HANDLE)0) // Registering Control Handler failed
		return;

	// Handle error condition 
	if (status != NO_ERROR)
	{
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwCheckPoint = 0;
		ServiceStatus.dwWaitHint = 0;
		ServiceStatus.dwWin32ExitCode = status;
		ServiceStatus.dwServiceSpecificExitCode = specificError;
		SetServiceStatus(hServiceStatus, &ServiceStatus);
		return;
	}

	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;
	if (!SetServiceStatus(hServiceStatus, &ServiceStatus))
		status = GetLastError();
	else
	{
		Sleep(5000); // Service main failed without sleep
		
		// ----------------------------- Main Function -----------------------------
		// NOTE : the full path of the test.bat is needed or it does not work. 
		
		HINSTANCE hReturnCode = ShellExecute(NULL, _T("open"), _T("C:\\Program Files\\FULL PARH\\test.bat"), NULL, NULL, SW_SHOWNORMAL);
	}

	// Stop Service
	//DebugPrintf(L"[!] Stopping the service: %s", serviceName);
	StopService(serviceName);
	free(serviceName);
	return;
}

