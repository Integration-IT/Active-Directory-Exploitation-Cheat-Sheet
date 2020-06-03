# -*- coding: utf-8 -*-
import sys
import ctypes
from ctypes import wintypes

READ_CONTROL = 0x00020000
STANDARD_RIGHTS_READ = READ_CONTROL
TOKEN_QUERY = 0x0008
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)


def can_get_admin_access():
    """
    Check if the user may be able to get administrator access.
    Returns True if the user is in the administrator's group.
    Otherwise returns False
    """
    SECURITY_MAX_SID_SIZE = 68
    WinBuiltinAdministratorsSid = 26
    ERROR_NO_SUCH_LOGON_SESSION = 1312
    ERROR_PRIVILEGE_NOT_HELD = 1314
    TokenLinkedToken = 19

    #  On XP or lower this is equivalent to has_root()
    if sys.getwindowsversion()[0] < 6:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())

    #  On Vista or higher, there's the whole UAC token-splitting thing.
    #  Many thanks for Junfeng Zhang for the workflow:
    # htttp://blogs.msdn.com/junfeng/archive/2007/01/26/how-to-tell-if-the-current-user-is-in-administrators-group-programmatically.aspx

    proc = ctypes.windll.kernel32.GetCurrentProcess()

    #  Get the token for the current process.
    try:
        token = ctypes.wintypes.HANDLE()
        ctypes.windll.advapi32.OpenProcessToken(proc, TOKEN_READ, ctypes.byref(token))
        try:
            #  Get the administrators SID.
            sid = ctypes.create_string_buffer(SECURITY_MAX_SID_SIZE)
            sz = ctypes.wintypes.DWORD(SECURITY_MAX_SID_SIZE)
            ctypes.windll.advapi32.CreateWellKnownSid(WinBuiltinAdministratorsSid, None, ctypes.byref(sid), ctypes.byref(sz))

            #  Check whether the token has that SID directly.
            has_admin = ctypes.wintypes.BOOL()
            ctypes.windll.advapi32.CheckTokenMembership(None, ctypes.byref(sid), ctypes.byref(has_admin))
            if has_admin.value:
                return True

            #  Get the linked token.  Failure may mean no linked token.
            ltoken = ctypes.wintypes.HANDLE()
            try:
                cls = TokenLinkedToken
                ctypes.windll.advapi32.GetTokenInformation(token, cls, ctypes.byref(ltoken), ctypes.sizeof(ltoken), ctypes.byref(sz))
            except WindowsError as e:
                if e.winerror == ERROR_NO_SUCH_LOGON_SESSION:
                    return False
                elif e.winerror == ERROR_PRIVILEGE_NOT_HELD:
                    return False
                else:
                    raise
            #  Check if the linked token has the admin SID
            try:
                ctypes.windll.advapi32.CheckTokenMembership(ltoken, ctypes.byref(sid), ctypes.byref(has_admin))
                return bool(has_admin.value)
            finally:
                ctypes.windll.kernel32.CloseHandle(ltoken)
        finally:
            ctypes.windll.kernel32.CloseHandle(token)
    except Exception:
        return None
    finally:
        try:
            ctypes.windll.kernel32.CloseHandle(proc)
        except Exception:
            pass

    return False
