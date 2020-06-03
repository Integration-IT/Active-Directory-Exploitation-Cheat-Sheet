# -*- coding: utf-8 -*-
try:
    import _winreg as winreg
except ImportError:
    import winreg

from ..objects.winstructures import OpenKey, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, KEY_READ


def registry_key_with_write_access(keys):
    """
    Return the service with write access on his key
    """
    results = []
    for sk in keys:
        if sk.is_key_writable and sk.is_key_writable not in results:
            if ('HKEY_LOCAL_MACHINE\\%s' % sk.is_key_writable) not in results:
                results.append('HKEY_LOCAL_MACHINE\\%s' % sk.is_key_writable)
    return results


def check_msi_misconfiguration():
    """
    Check if MSI files are always launched with SYSTEM privileges if AlwaysInstallElevated registry key is set
    """
    try:
        hklm = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', 0, KEY_READ)
        hkcu = OpenKey(HKEY_CURRENT_USER, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', 0, KEY_READ)
        if int(winreg.QueryValueEx(hklm, 'AlwaysInstallElevated')[0]) != 0 and int(
                winreg.QueryValueEx(hkcu, 'AlwaysInstallElevated')[0]) != 0:
            return True
    except Exception:
        pass
    return False
