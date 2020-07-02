# -*- encoding: utf-8 -*-
import os
import traceback

from .files.files import File
from .files.file_manager import FileManager


class Services(object):
    """
    Services checks
    """

    def __init__(self):
        self.fm = FileManager()
        self.list = self._get_services_systemd()

    def _get_services_systemd(self):
        """
        Get list of services using dbus
        """
        try:
            import dbus
        except ImportError:
            return []

        objects = []
        try:
            sys_bus = dbus.SystemBus()
            systemd = sys_bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
            list_units = systemd.get_dbus_method('ListUnits', 'org.freedesktop.systemd1.Manager')

            for unit, description, loaded, active, status, _, sd_object, _, _, _ in list_units():
                if not unit.endswith('.service'):
                    continue

                unit_object = sys_bus.get_object('org.freedesktop.systemd1', sd_object)
                service_iface = dbus.Interface(unit_object, 'org.freedesktop.DBus.Properties')
                properties = service_iface.GetAll('org.freedesktop.systemd1.Service')

                exec_start = properties.get('ExecStart')
                if not len(exec_start):
                    continue

                exec_start = exec_start[-1]

                argv0, argv = exec_start[0], exec_start[1]
                binpath = None

                argv0 = unicode(argv0)
                argv = [unicode(x) for x in argv]

                if os.path.basename(argv0) == os.path.basename(argv[0]):
                    binpath = argv0
                else:
                    binpath = '{}| {}'.format(argv0, argv[0])

                if len(argv) > 1:
                    binpath += ' ' + ' '.join([x if ' ' not in x else repr(x) for x in argv[1:]])

                objects.append({
                    'name': unicode(unit),
                    'display_name': unicode(description),
                    'status': unicode(status),
                    'pid': int(properties.get('MainPID')) or None,
                    'binpath': unicode(binpath),
                    'files_object': self.fm.extract_paths_from_string(binpath),
                    'username': unicode(properties.get('User'))
                })
        except Exception:
            print(traceback.format_exc())

        return objects

    def write_access_on_binpath(self, user):
        """
        Return services if a path contained in binpath is writable. 
        A binpath could contains mutliple paths so each files are checked if there are writable. 
        """
        has_write_access = []
        for service in self.list:
            values = {
                'service': service.get('name'),
                'line': service.get('binpath'),
                'binpath': []
            }

            for file in service.get('files_object'):
                if file.is_writable(user):
                    values['binpath'].append('[writable] => %s' % file.path)

                # Check if directory is writable
                directory = File(file.dirname)
                if directory.is_writable(user):
                    if 'directory' not in values:
                        values['directory'] = []

                    if '[writable] => %s' % directory.path not in values['directory']:
                        values['directory'].append('[writable] => %s' % directory.path)

            if values['binpath']:
                has_write_access.append(values)

        return has_write_access


if __name__ == '__main__':

    for service in Services.list():
        line = '{:<50}{}'.format(service.get('name'), service.get('binpath'))
        print(line)
