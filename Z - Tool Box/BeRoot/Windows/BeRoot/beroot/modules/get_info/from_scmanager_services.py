# -*- coding: utf-8 -*-
from ctypes.wintypes import *
import ctypes

from ..checks.path_manipulation_checks import get_path_info
from ..objects.service import Service
from ..objects.winstructures import SERVICE_START, SERVICE_STOP, SERVICE_CHANGE_CONFIG, SERVICE_QUERY_CONFIG, \
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, QUERY_SERVICE_CONFIG, \
    OpenService, CloseServiceHandle, OpenSCManager, QueryServiceConfig, EnumServicesStatus, \
    ERROR_INSUFFICIENT_BUFFER, LPQUERY_SERVICE_CONFIG


class GetServices(object):

    def get_services(self, services_loaded):
        """
        Generate the list of services
        """
        scm = OpenSCManager(None, None, SC_MANAGER_ENUMERATE_SERVICE)

        for i in EnumServicesStatus(scm): 
            hservice = OpenService(scm, i.ServiceName, SERVICE_QUERY_CONFIG)
            bytes_needed = DWORD()
            
            QueryServiceConfig(hservice, 0, 0, ctypes.byref(bytes_needed))
            while ctypes.GetLastError() == ERROR_INSUFFICIENT_BUFFER:
                if bytes_needed.value < ctypes.sizeof(QUERY_SERVICE_CONFIG): 
                    break 
                services_buffer = ctypes.create_string_buffer("", bytes_needed.value)
                success = QueryServiceConfig(hservice, ctypes.byref(services_buffer), bytes_needed, ctypes.byref(bytes_needed))
                lpServicesArray = ctypes.cast(ctypes.cast(ctypes.pointer(services_buffer), ctypes.c_void_p), LPQUERY_SERVICE_CONFIG)
                if success: break

            CloseServiceHandle(hservice)

            short_name = i.ServiceName
            full_path = lpServicesArray.contents.lpBinaryPathName

            sv = self.check_if_service_already_loaded(short_name, full_path, services_loaded)
            if sv:
                sv.permissions = self.get_service_permissions(sv)

            if not sv:
                sk = Service()
                sk.name = short_name
                sk.display_name = i.DisplayName
                sk.full_path = full_path
                sk.paths = get_path_info(full_path)
                sk.permissions = self.get_service_permissions(sv)
                services_loaded.append(sk)

        return services_loaded

    def check_if_service_already_loaded(self, name, full_path, services_loaded):
        """
        Check if the service has already been loaded from registry
        """
        for service in services_loaded:
            if service.full_path == full_path and service.name == name:
                return service
        return False

    def get_service_permissions(self, s):
        """
        Check service permission of a service (if it can be started, stopped or modified)
        """
        hnd = OpenSCManager(None, None, SC_MANAGER_CONNECT)

        start = self.service_start(hnd, s)
        stop = self.service_stop(hnd, s)
        change_config = self.change_sercice_configuration(hnd, s)

        return {'start': start, 'stop': stop, 'change_config': change_config}

    def service_start(self, hnd, s):
        """
        Check if a service can be started
        """
        try:
            sv = OpenService(hnd, s.name, SERVICE_START)
            if sv: 
                return True
        except Exception:
            pass
        
        return False

    def service_stop(self, hnd, s):
        """
        Check if a service can be stopped
        """
        try:
            sv = OpenService(hnd, s.name, SERVICE_STOP)
            if sv:
                return True
        except Exception:
            pass
        
        return False

    def change_sercice_configuration(self, hnd, s):
        """
        Check if the configuration of a service can be changed
        """
        try:
            sv = OpenService(hnd, s.name, SERVICE_CHANGE_CONFIG)
            if sv:
                return True
        except Exception:
            pass

        return False
