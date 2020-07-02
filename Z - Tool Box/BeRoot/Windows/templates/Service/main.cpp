#include "service.h"

int main(int argc, char **argv)
{
	SERVICE_TABLE_ENTRY serviceTable[2];
	serviceTable[0].lpServiceName = SERVICE_NAME;
	serviceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	serviceTable[1].lpServiceName = NULL;
	serviceTable[1].lpServiceProc = NULL;

	if (StartServiceCtrlDispatcher(serviceTable))	// => Check ServiceMain
		return 0;
}