# -*- coding: utf-8 -*-
from ctypes.wintypes import *
from ctypes import *

try:
    import _winreg as winreg
except ImportError:
    import winreg

from ..get_info.system_info import System


DWORD = c_uint32
LPVOID = c_void_p
LONG = c_long

INVALID_HANDLE_VALUE = c_void_p(-1).value

HKEY_LOCAL_MACHINE = -2147483646
HKEY_CURRENT_USER = -2147483647

KEY_READ = 131097
KEY_WRITE = 131078
KEY_ENUMERATE_SUB_KEYS = 8
KEY_QUERY_VALUE = 1

REG_EXPAND_SZ = 2
REG_DWORD = 4

LPCTSTR = LPSTR
LPDWORD = POINTER(DWORD)

SC_MANAGER_CONNECT = 1
SC_MANAGER_CREATE_SERVICE = 2
SC_MANAGER_ENUMERATE_SERVICE = 4

SERVICE_START_PENDING = 2
SERVICE_START = 16
SERVICE_STOP = 32
SERVICE_CONTROL_STOP = 1
SERVICE_RUNNING = 4
SERVICE_QUERY_STATUS = 4
SERVICE_CHANGE_CONFIG = 2
SERVICE_QUERY_CONFIG = 1

SERVICE_KERNEL_DRIVER = 1
SERVICE_FILE_SYSTEM_DRIVER = 2
SERVICE_ADAPTER = 4
SERVICE_RECOGNIZER_DRIVER = 8
SERVICE_WIN32_OWN_PROCESS = 16
SERVICE_WIN32_SHARE_PROCESS = 32
SERVICE_WIN32 = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
SERVICE_INTERACTIVE_PROCESS = 256
SERVICE_DRIVER = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER
SERVICE_TYPE_ALL = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS

SERVICE_ACTIVE = 1
SERVICE_INACTIVE = 2
SERVICE_STATE_ALL = 3

ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234

SE_PRIVILEGE_ENABLED            = (0x00000002)

STANDARD_RIGHTS_REQUIRED        = 0x000F0000L
TOKEN_ASSIGN_PRIMARY            = 0x0001
TOKEN_DUPLICATE                 = 0x0002
TOKEN_IMPERSONATE               = 0x0004
TOKEN_QUERY                     = 0x0008
TOKEN_QUERY_SOURCE              = 0x0010
TOKEN_ADJUST_PRIVILEGES         = 0x0020
TOKEN_ADJUST_GROUPS             = 0x0040
TOKEN_ADJUST_DEFAULT            = 0x0080
TOKEN_ADJUST_SESSIONID          = 0x0100
TOKEN_ALL_ACCESS                = (
    STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | \
    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | \
    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | \
    TOKEN_ADJUST_SESSIONID)

LOGON32_LOGON_INTERACTIVE = 2
LOGON32_PROVIDER_DEFAULT = 0


class SERVICE_STATUS(Structure):
    _fields_ = [
        ('dwServiceType', DWORD),
        ('dwCurrentState', DWORD),
        ('dwControlsAccepted', DWORD),
        ('dwWin32ExitCode', DWORD),
        ('dwServiceSpecificExitCode', DWORD),
        ('dwCheckPoint', DWORD),
        ('dwWaitHint', DWORD),
    ]
PSERVICE_STATUS = POINTER(SERVICE_STATUS)


class QUERY_SERVICE_CONFIG(Structure):
    _fields_ = [
        ('dwServiceType', DWORD),
        ('dwStartType', DWORD),
        ('dwErrorControl', DWORD),
        ('lpBinaryPathName', LPSTR),
        ('lpLoadOrderGroup', LPSTR),
        ('dwTagId', DWORD),
        ('lpDependencies', LPSTR),
        ('lpServiceStartName', LPSTR),
        ('lpDisplayName', LPSTR),
    ]
LPQUERY_SERVICE_CONFIG = POINTER(QUERY_SERVICE_CONFIG)


class ENUM_SERVICE_STATUSA(Structure):
    _fields_ = [
        ('lpServiceName', LPSTR),
        ('lpDisplayName', LPSTR),
        ('ServiceStatus', SERVICE_STATUS),
    ]
LPENUM_SERVICE_STATUSA = POINTER(ENUM_SERVICE_STATUSA)

class ServiceStatusEntry(object): 
    """ 
    Service status entry returned by L{EnumServicesStatus}. 
    """ 
    def __init__(self, raw): 
        """ 
        @type  raw: L{ENUM_SERVICE_STATUSA} or L{ENUM_SERVICE_STATUSW} 
        @param raw: Raw structure for this service status entry. 
        """ 
        self.ServiceName             = raw.lpServiceName 
        self.DisplayName             = raw.lpDisplayName 
        self.ServiceType             = raw.ServiceStatus.dwServiceType 
        self.CurrentState            = raw.ServiceStatus.dwCurrentState 
        self.ControlsAccepted        = raw.ServiceStatus.dwControlsAccepted 
        self.Win32ExitCode           = raw.ServiceStatus.dwWin32ExitCode 
        self.ServiceSpecificExitCode = raw.ServiceStatus.dwServiceSpecificExitCode 
        self.CheckPoint              = raw.ServiceStatus.dwCheckPoint 
        self.WaitHint                = raw.ServiceStatus.dwWaitHint 


class TOKEN_INFORMATION_CLASS:
    #see http://msdn.microsoft.com/en-us/library/aa379626%28VS.85%29.aspx
    TokenUser       = 1
    TokenGroups     = 2
    TokenPrivileges = 3

class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]

    def __eq__(self, other):
        return (self.HighPart == other.HighPart and self.LowPart == other.LowPart)

    def __ne__(self, other):
        return not (self==other)

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]

    def is_enabled(self):
        return bool(self.Attributes & SE_PRIVILEGE_ENABLED)

    def enable(self):
        self.Attributes |= SE_PRIVILEGE_ENABLED

    def get_name(self):
        size = DWORD(10240)
        buf = create_unicode_buffer(size.value)
        res = LookupPrivilegeName(None, self.Luid, buf, size)

        if res == 0:
            raise WinError(GetLastError())

        return buf[:size.value]

    def __str__(self):
        res = self.get_name()

        if self.is_enabled():
            res += ' (enabled)'

        return res

class TOKEN_PRIVS(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES*0),
    ]

    def get_array(self):
        array_type = LUID_AND_ATTRIBUTES*self.PrivilegeCount
        privileges = cast(self.Privileges, POINTER(array_type)).contents
        return privileges

    def __iter__(self):
        return iter(self.get_array())


advapi32 = windll.advapi32
kernel32 = WinDLL('kernel32', use_last_error=True)

OpenSCManager = advapi32.OpenSCManagerA
OpenSCManager.argtypes = [LPCTSTR, LPCTSTR, DWORD]
OpenSCManager.restype = HANDLE

OpenService = advapi32.OpenServiceA
OpenService.argtypes = [HANDLE, LPCTSTR, DWORD]
OpenService.restype = HANDLE

CloseServiceHandle = advapi32.CloseServiceHandle
CloseServiceHandle.argtypes = [HANDLE]
CloseServiceHandle.restype = BOOL

ControlService = advapi32.ControlService
ControlService.argtypes = [HANDLE, DWORD, PSERVICE_STATUS]
ControlService.restype = BOOL

StartService = advapi32.StartServiceA
StartService.argtypes = [HANDLE, DWORD, c_void_p]
StartService.restype = BOOL

GetServiceKeyName = advapi32.GetServiceKeyNameA
GetServiceKeyName.argtypes = [HANDLE, LPCTSTR, LPCTSTR, LPDWORD]
GetServiceKeyName.restype = BOOL

QueryServiceStatus = advapi32.QueryServiceStatus
QueryServiceStatus.argtypes = [HANDLE, PSERVICE_STATUS]
QueryServiceStatus.restype = BOOL

QueryServiceConfig = advapi32.QueryServiceConfigA
QueryServiceConfig.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD]
QueryServiceConfig.restype = BOOL

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.restype = BOOL
OpenProcessToken.argtypes = [HANDLE, DWORD, POINTER(HANDLE)]

GetTokenInformation = advapi32.GetTokenInformation
GetTokenInformation.restype = BOOL
GetTokenInformation.argtypes = [HANDLE, DWORD, LPVOID, DWORD, POINTER(DWORD)]

LookupPrivilegeName = advapi32.LookupPrivilegeNameW
LookupPrivilegeName.argtypes = [LPWSTR, POINTER(LUID), LPWSTR, POINTER(DWORD)]
LookupPrivilegeName.restype = BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.restype = HANDLE
GetCurrentProcess.argtypes = []

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = [HANDLE]

LogonUser = advapi32.LogonUserA
LogonUser.argtypes = [LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, POINTER(HANDLE)]
LogonUser.restype = BOOL

GetUserNameW  = advapi32.GetUserNameW
GetUserNameW.argtypes = [LPWSTR, POINTER(DWORD)]
GetUserNameW.restype = BOOL

s = System()


def OpenKey(key, path, index, access):
    if s.isx64:
        return winreg.OpenKey(key, path, index, access | winreg.KEY_WOW64_64KEY)
    else:
        return winreg.OpenKey(key, path, index, access)


def EnumServicesStatus(hSCManager, dwServiceType=SERVICE_DRIVER | SERVICE_WIN32, dwServiceState=SERVICE_STATE_ALL): 
        _EnumServicesStatusA = advapi32.EnumServicesStatusA 
        _EnumServicesStatusA.argtypes = [SC_HANDLE, DWORD, DWORD, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD] 
        _EnumServicesStatusA.restype  = bool 

        cbBytesNeeded    = DWORD(0) 
        services_returned = DWORD(0) 
        ResumeHandle     = DWORD(0) 

        _EnumServicesStatusA(hSCManager, dwServiceType, dwServiceState, None, 0, byref(cbBytesNeeded), byref(services_returned), byref(ResumeHandle)) 

        Services = [] 
        success = False 
        while GetLastError() == ERROR_MORE_DATA: 
                if cbBytesNeeded.value < sizeof(ENUM_SERVICE_STATUSA): 
                        break 
                services_buffer = create_string_buffer("", cbBytesNeeded.value) 
                success = _EnumServicesStatusA(hSCManager, dwServiceType, dwServiceState, byref(services_buffer), sizeof(services_buffer), byref(cbBytesNeeded), byref(services_returned), byref(ResumeHandle)) 
                if sizeof(services_buffer) < (sizeof(ENUM_SERVICE_STATUSA) * services_returned.value): 
                        raise WinError() 
                lpServicesArray = cast(cast(pointer(services_buffer), c_void_p), LPENUM_SERVICE_STATUSA) 
                for index in range(0, services_returned.value):
                        Services.append(ServiceStatusEntry(lpServicesArray[index])) 
                if success: break 
        if not success: 
                raise WinError() 

        return Services 


def get_process_token():
    """
    Get the current process token
    """
    token = HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, token):
        raise WinError(GetLastError())

    return token


def get_currents_privs():
    '''
    Get all privileges associated with the current process.
    '''
    dwSize = DWORD()
    hToken = get_process_token()

    try:
        if not GetTokenInformation(
            hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, None, 0, byref(dwSize)):

            error = GetLastError()
            # print error
            if error != ERROR_INSUFFICIENT_BUFFER:
                raise WinError(error)

        cBuffer = create_string_buffer(dwSize.value)
        if not GetTokenInformation(
            hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges,
            cBuffer, dwSize.value, byref(dwSize)):
            raise WinError(GetLastError())

    finally:
        CloseHandle(hToken)

    privs = tuple(
        (x.get_name(), x.is_enabled()) for x in cast(
            cBuffer, POINTER(TOKEN_PRIVS)).contents
    )

    return privs


def GetUserName():
    nSize = DWORD(0)
    GetUserNameW(None, byref(nSize))
    error = GetLastError()

    if error and error != ERROR_INSUFFICIENT_BUFFER:
        raise WinError(error)

    lpBuffer = create_unicode_buffer(u'', nSize.value + 1)

    if not GetUserNameW(lpBuffer, byref(nSize)):
        raise WinError(get_last_error())

    return lpBuffer.value


def to_unicode(x):
    tx = type(x)
    if tx == str:
        return x.decode(sys.getfilesystemencoding())
    elif tx == unicode:
        return x
    else:
        return str(x)


def try_empty_login(username):
    hToken = HANDLE(INVALID_HANDLE_VALUE)
    logged_on = LogonUser(username, "", None, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, byref(hToken))
    if logged_on or GetLastError() == 1327:
        return True
    return False
