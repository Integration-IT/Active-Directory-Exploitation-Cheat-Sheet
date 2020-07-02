# -*- coding: utf-8 -*-
import traceback

from .modules.checks.path_manipulation_checks import is_root_dir_writable, space_and_no_quotes, \
    exe_with_writable_directory
from .modules.checks.services_checks import check_services_creation_with_openscmanager, check_service_permissions
from .modules.checks.filesystem_checks import check_unattended_files, check_sysprep_files, \
    checks_writeable_directory_on_path_environment_variable, check_well_known_dll_injections
from .modules.checks.privileges import check_currrent_user_privilege
from .modules.checks.users import check_empty_passwords, check_passwordreq_option
from .modules.checks.registry_checks import registry_key_with_write_access, check_msi_misconfiguration
from .modules.checks.system import can_get_admin_access
from .modules.get_info.users_info import Users
from .modules.get_info.from_scmanager_services import GetServices
from .modules.get_info.from_registry import Registry
from .modules.get_info.from_taskscheduler import GetTaskschedulers
from .modules.get_info.softwares_list import Softwares
from .modules.get_info.system_info import System


class RunChecks(object):

    def __init__(self):

        # Load info from registry
        r = Registry()
        self.service = r.get_services_from_registry()
        self.startup = r.get_sensitive_registry_key()

        # Load info using the SCManager
        s = GetServices()
        self.service = s.get_services(self.service)

        # Check taskscheduler
        self.t = GetTaskschedulers()
        self.task = self.t.tasks_list()

        self.softwares = Softwares()

    def tab_of_dict_to_string(self, tab):
        '''
        Convert a tab of dic to a string
        '''
        string = ''
        for values in tab:
            for value in values:
                if 'list' in str(type(values[value])):
                    string += '%s\n' % str(value)
                    for w in values[value]:
                        string += '\t- %s\n' % w
                else:
                    string += '%s: %s\n' % (value, str(values[value]))
            string += '\n'
        return string

    def tab_to_string(self, tab):
        '''
        Convert a tab of string into a string
        '''
        string = ''
        for value in tab:
            string += '%s\n' % value
        return string

    def bool_to_string(self, value):
        '''
        Convert a bool to a string
        '''
        return str(value)

    def _check_registry_misconfiguration(self, obj):
        '''
        Check registry misconfiguration
        '''
        return [
            (
                'Registry key with writable access', 
                self.tab_to_string(registry_key_with_write_access(obj))
            )
        ]

    def _check_path_misconfiguration(self, obj):
        '''
        Check path misconfiguration
        '''
        return [
            (
                'Path containing spaces without quotes', 
                self.tab_of_dict_to_string(space_and_no_quotes(obj))
            ), 
            (
                'Binary located on a writable directory', 
                self.tab_of_dict_to_string(exe_with_writable_directory(obj))
            )
        ]

    def get_services_vuln(self):
        '''
        Services
        '''
        return {
            'category': 'Service',
            'results': [
                (
                    'Permission to create a service with openscmanager', 
                    self.bool_to_string(check_services_creation_with_openscmanager())
                ), 
                (
                    'Check for services whose configuration could be modified', 
                    self.tab_of_dict_to_string(check_service_permissions(self.service))
                )
            ] +  self._check_path_misconfiguration(self.service)
            + self._check_registry_misconfiguration(self.service)
        }

    def get_startup_key_vuln(self):
        '''
        Start up keys
        '''
        return {
            'category': 'Startup Keys',
            'results': 
                self._check_registry_misconfiguration(self.startup) + 
                self._check_path_misconfiguration(self.startup)
        }

    def get_msi_configuration(self):
        '''
        MSI configuration
        '''
        return {
            'category': 'MSI misconfiguration',
            'results': [
                (
                    'MSI file launched with SYSTEM privileges', 
                    self.bool_to_string(check_msi_misconfiguration())
                )
            ]
        }

    def get_tasks_vulns(self):
        '''
        Taskscheduler
        '''
        return {
            'category': 'Taskscheduler',
            'results': [
                (
                    'Permission to write on the task directory: %s' % self.t.task_directory, 
                    self.bool_to_string(is_root_dir_writable(self.t.task_directory))
                )
            ] +  self._check_path_misconfiguration(self.task)
        }

    def get_interesting_files(self):
        '''
        Interesting files on the file system
        '''
        return {
            'category': 'Interesting files',
            'results': [
                (
                    'Unattended files', 
                     self.tab_to_string(check_unattended_files())
                ), 
                (
                    'Sysprep files', 
                    self.tab_to_string(check_sysprep_files())
                )
            ]
        }

    def get_installed_softwares(self):
        '''
        Useful to find Windows Redistributable version or software vulnerable
        '''
        sof_list = []
        for soft in self.softwares.list_softwares:
            sof_list.append('%s %s' % (soft.name, soft.version))

        return {
            'category': 'Softwares',
            'results': [
                (
                    'Softwares installed', 
                     self.tab_to_string(sof_list)
                ), 
                (
                    'AV installed', 
                    self.tab_to_string(self.softwares.get_av_software())
                )
            ]
        }

    def get_local_account_info(self):
        '''
        Check local accounts hardening
        '''
        users = Users()
        return {
            'category': 'Local Account',
            'results': [
                (
                    'Is current user in the Administrators group', 
                    self.bool_to_string(can_get_admin_access())
                ), 
                (
                    'Current privileges', 
                    self.tab_to_string(check_currrent_user_privilege())
                ), 
                (
                    'Empty password found for local users', 
                    self.tab_to_string(check_empty_passwords(users))
                ),
                (
                    'PasswordReq is set to no for users', 
                    self.tab_to_string(check_passwordreq_option(users))
                )
            ]
        }


    def get_well_known_dll_injections(self):
        '''
        This technique should not work on windows 10
        '''
        # From msdn: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
        # 6.0 => Windows Vista  /   Windows Server 2008
        # 6.1 => Windows 7      /   Windows Server 2008 R2
        # 6.2 => Windows 8      /   Windows Server 2012
        results = [(None, None)]
        s = System()
        if s.get_os_version() in ['6.0', '6.1', '6.2']:
            results = [(
                'Writeable path on the path environment variable', 
                self.tab_to_string(checks_writeable_directory_on_path_environment_variable())
            ),
            (
                'Presence of well known vulnerable services', 
                self.tab_of_dict_to_string(check_well_known_dll_injections(self.service))
            )]

        return {
            'category': 'Well known dlls hijacking',
            'results': results
        }


def get_sofwares():
    checks = RunChecks()
    yield checks.get_installed_softwares()


def check_all():
    checks = RunChecks()
    found = False

    to_checks = [
        checks.get_msi_configuration,  # Check msi misconfiguration
        checks.get_services_vuln,  # Service checks
        checks.get_startup_key_vuln,  # Startup keys checks
        checks.get_tasks_vulns,  # Taskschedulers checks
        checks.get_interesting_files,  # Interesting files checks
        # checks.get_installed_softwares, # Softwares checks
        checks.get_local_account_info,  # System if already admin (uac not bypassed yet)
        checks.get_well_known_dll_injections,  # Well known windows services vulnerable to dll hijacking
    ]

    for c in to_checks:
        try:
            results = c()
            for desc, result in results.get('results'):
                # Boolean has been changed to string so this check is needed
                if result and result != 'False':
                    found = True
                    yield results
                    break
        except Exception:
            yield {
                'category': 'error on: %s' % str(c.__name__),
                'error': traceback.format_exc()
            }

    if not found:
        yield {
            'category': 'No Luck',
            'error': '\nNothing found !'
        }


def run():
    results = []
    for r in check_all():
        results.append(r)
    return results
