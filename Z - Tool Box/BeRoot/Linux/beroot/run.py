#!/usr/bin/env python
# -*- coding: utf-8 -*-
from .modules.users import Users
from .modules.services import Services
from .modules.suid import SuidBins
from .modules.interesting_files import InterestingFiles
from .modules.gtfobins import GTFOBins
from .modules.sudo.sudoers_file import SudoersFile
from .modules.sudo.sudo_list import SudoList
from .modules.useful.useful import tab_of_dict_to_string, tab_to_string
from .checks.checks import (
    check_sudoers_misconfigurations, is_docker_installed, check_nfs_root_squashing,
    get_capabilities, get_exploits, check_python_library_hijacking, get_ptrace_scope
)


class RunChecks(object):

    def __init__(self, password):
        self.current_user = Users().current
        self.services = Services()
        self.file_info = InterestingFiles()
        self.gtfobins = GTFOBins()
        self.sudofile = SudoersFile()
        self.sudolist = SudoList(password)
        self.suids = SuidBins(self.gtfobins)

    def file_permissions(self):
        """
        Files too permissive
        """
        return (
            'Interesting files with write access',
            tab_of_dict_to_string(self.file_info.write_access_on_files(self.current_user))
        )

    def services_files_permissions(self):
        """
        Services with path too permissive
        """
        return (
            'Services ',
            tab_of_dict_to_string(self.services.write_access_on_binpath(self.current_user))
        )

    def suid_bins(self):
        """
        List Suid bins
        """
        return (
            'Suid Binaries ',
            tab_of_dict_to_string(self.suids.check_suid_bins(
                self.current_user),
                new_line=False, 
                title=False,
            )
        )

    def sudoers_misconfiguration(self):
        """
        Sudoers file (/etc/sudoers) 
        """
        rules = self.sudofile.rules_from_sudoers_file()
        return (
            'Sudoers file',
            check_sudoers_misconfigurations(self.file_info, self.services, self.suids, self.current_user, rules)
        )

    def sudo_list(self):
        """
        Sudo rules from sudo -ll output 
        """
        rules = self.sudolist.rules_from_sudo_ll()
        return (
            'Sudo rules',
            check_sudoers_misconfigurations(self.file_info, self.services, self.suids, self.current_user, rules)
        )

    def sudo_dirty_check(self):
        """
        Dirty check to be sure we not forgot a simple rules
        """
        return (
            'Sudo -i',
            self.sudolist.dirty_check(),
        )

    def docker_installed(self):
        """
        Check if docker is present
        """
        return (
            'Docker',
            is_docker_installed(),
        )

    def nfs_root_squashing(self):
        """
        Check NFS Root Squashing - /etc/exports
        """
        return (
            'Root Squashing - /etc/exports',
            check_nfs_root_squashing(),
        )

    def ldpreload(self):
        """
        Check if LD_PRELOAD has been found in env_keep directive (sudoers rules)
        """
        return (
            'LD_PRELOAD',
            'Directive found' if self.sudofile.ld_preload or self.sudolist.ld_preload else False
        )

    def capabilities(self):
        """
        List capabilities from binaries located on /usr/bin/ and /usr/sbin/
        """
        return (
            'Capabilities',
            get_capabilities()
        )

    def python_library_hijacking(self):
        """
        Python Library Hijacking
        """
        return (
            'Writable Python Library Directory',
            tab_to_string(check_python_library_hijacking(self.current_user)),
        )

    def ptrace_scope(self):
        """
        Check ptrace scope stored in /proc/sys/kernel/yama/ptrace_scope
        """
        return (
            'Ptrace Scope',
            get_ptrace_scope()
        )

    def exploits(self):
        """
        Run Linux exploit suggester
        """
        return (
            'Exploits',
            get_exploits()
        )


def print_output(output, to_print):
    category, result = output
    st = ''
    if result:
        st = '\n################ {category} ################\n\n{result}'.format(category=category, result=result)

        if to_print:
            print(st)

    return st


def run(password, to_print=True):
    """
    Can be useful when called from other tools - as a package
    beroot.py is not needed anymore
    This function returns all results found
    """
    total_found = ''

    checks = RunChecks(password)
    to_checks = [
        checks.file_permissions,
        checks.services_files_permissions,
        checks.suid_bins,
        checks.sudoers_misconfiguration,
        checks.sudo_list,
        checks.sudo_dirty_check,
        checks.docker_installed,
        checks.nfs_root_squashing,
        checks.ldpreload,
        checks.capabilities,
        checks.ptrace_scope,
        checks.exploits,
        checks.python_library_hijacking,
    ]

    for c in to_checks:
        results = c()

        total_found += print_output(results, to_print=to_print)

    return total_found
