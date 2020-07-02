# -*- coding: utf-8 -*-
import ctypes
from ..objects.winstructures import OpenSCManager, SC_MANAGER_CREATE_SERVICE


def check_services_creation_with_openscmanager():
    """
    Check if a service can be created
    """
    try:
        # Open the SCM with "SC_MANAGER_CREATE_SERVICE" rights
        create_service = OpenSCManager(None, None, SC_MANAGER_CREATE_SERVICE)
        if ctypes.GetLastError() == 0:
            return True
    except Exception:
        pass

    return False


def check_service_permissions(services):
    """
    Returns all services that could be modified
    """
    results = []
    for service in services:
        if 'change_config' in service.permissions:
            if service.permissions['change_config']:
                results.append(
                    {
                        'Name': str(service.name),
                        'Display Name': str(service.display_name),
                        'Permissions': 'change config: %s / start: %s / stop: %s' % (
                            service.permissions['change_config'],
                            service.permissions['start'],
                            service.permissions['stop']
                        )
                    }
                )
    return results
