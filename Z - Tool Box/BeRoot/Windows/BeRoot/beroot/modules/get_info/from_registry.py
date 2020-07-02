# -*- coding: utf-8 -*-
import os

try:
    import _winreg as winreg
except ImportError:
    import winreg

from ..checks.path_manipulation_checks import get_path_info
from ..objects.service import Service
from ..objects.registry import RegistryKey
from ..objects.winstructures import KEY_READ, KEY_WRITE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, HKEY_LOCAL_MACHINE, OpenKey


class Registry(object):

    # --------------------------------------- StartUp Key functions ---------------------------------------

    def define_path(self):
        runkeys_hklm = [
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
            r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
            r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
        ]
        return runkeys_hklm

    def get_sensitive_registry_key(self):
        """
        Read all startup key
        """
        keys = []
        runkeys_hklm = self.define_path()

        # Access either in read only mode, or in write mode
        access_read = KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
        access_write = KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE

        # Loop through all keys to check
        for keyPath in runkeys_hklm:
            is_key_writable = False

            # Check if the registry key has writable access
            try:
                hkey = OpenKey(HKEY_LOCAL_MACHINE, keyPath, 0, access_write)
                is_key_writable = keyPath
            except Exception:
                try:
                    hkey = OpenKey(HKEY_LOCAL_MACHINE, keyPath, 0, access_read)
                except Exception:
                    continue

            # Retrieve all value of the registry key
            try:
                num = winreg.QueryInfoKey(hkey)[1]

                # Loop through number of value in the key
                for x in range(0, num):
                    k = winreg.EnumValue(hkey, x)

                    stk = RegistryKey()
                    if is_key_writable:
                        stk.is_key_writable = is_key_writable

                    stk.key = keyPath
                    stk.name = k[0]
                    stk.full_path = k[1]
                    stk.paths = get_path_info(k[1])

                    keys.append(stk)
                winreg.CloseKey(hkey)
            except Exception:
                pass

        return keys

    # --------------------------------------- Service Key functions ---------------------------------------

    def get_services_from_registry(self):
        """
        Read all service information from registry
        """
        service_keys = []

        # Open the Base on read only
        access_read = KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
        access_write = KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE

        hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services', 0, access_read)
        num = winreg.QueryInfoKey(hkey)[0]

        # Loop through all subkeys
        for x in range(0, num):
            sk = Service()

            # Name of the service
            svc = winreg.EnumKey(hkey, x)
            sk.name = svc

            # ------ Check Write access of the key ------
            try:
                sk.key = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s" % svc
                skey = OpenKey(hkey, svc, 0, access_write)
                sk.is_key_writable = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s" % svc
            except Exception:
                skey = OpenKey(hkey, svc, 0, access_read)
                pass

            # ------ Check if the key has the Parameters\Application value presents ------
            try:
                # Find display name
                display_name = str(winreg.QueryValueEx(skey, 'DisplayName')[0])
                if display_name:
                    sk.display_name = display_name
            except Exception:
                # In case there is no key called DisplayName
                pass

            # ------ Check if the key has his executable with write access and the folder containing it as well ------
            try:
                skey = OpenKey(hkey, svc, 0, access_read)

                # Find ImagePath name
                image_path = str(winreg.QueryValueEx(skey, 'ImagePath')[0])

                if image_path:
                    image_path = os.path.expandvars(image_path)

                    if 'drivers' not in image_path.lower():
                        sk.full_path = image_path
                        sk.paths = get_path_info(image_path)
            except Exception:
                pass

            service_keys.append(sk)
        return service_keys
