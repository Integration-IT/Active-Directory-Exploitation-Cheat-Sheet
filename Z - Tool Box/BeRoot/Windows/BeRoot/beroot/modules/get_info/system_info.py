# -*- coding: utf-8 -*-
import ctypes
import os


class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [('dwOSVersionInfoSize', ctypes.c_ulong),
                ('dwMajorVersion', ctypes.c_ulong),
                ('dwMinorVersion', ctypes.c_ulong),
                ('dwBuildNumber', ctypes.c_ulong),
                ('dwPlatformId', ctypes.c_ulong),
                ('szCSDVersion', ctypes.c_wchar * 128),
                ('wServicePackMajor', ctypes.c_ushort),
                ('wServicePackMinor', ctypes.c_ushort),
                ('wSuiteMask', ctypes.c_ushort),
                ('wProductType', ctypes.c_byte),
                ('wReserved', ctypes.c_byte)]


class System(object):
    def __init__(self):
        self.isx64 = self.isx64machine()

    def get_os_version(self):
        os_version = OSVERSIONINFOEXW()
        os_version.dwOSVersionInfoSize = ctypes.sizeof(os_version)
        retcode = ctypes.windll.Ntdll.RtlGetVersion(ctypes.byref(os_version))
        if retcode != 0:
            return False

        return '%s.%s' % (str(os_version.dwMajorVersion.real), str(os_version.dwMinorVersion.real))

    def isx64machine(self):
        archi = os.environ.get("PROCESSOR_ARCHITEW6432", '')
        if '64' in archi:
            return True

        archi = os.environ.get("PROCESSOR_ARCHITECTURE", '')
        if '64' in archi:
            return True

        return False
