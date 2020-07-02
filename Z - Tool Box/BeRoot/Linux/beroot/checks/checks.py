#!/usr/bin/env python
# -*- coding: utf-8 -*-
import getpass
import os
import sys

from ..modules.exploit import Exploit
from ..modules.files.files import File
from ..modules.sudo.sudo import Sudo
from ..modules.useful.useful import tab_of_dict_to_string, tab_to_string, run_cmd


def is_docker_installed():
    """
    Check if docker service is present
    """
    return "/etc/init.d/docker found" if os.path.exists('/etc/init.d/docker') else False


def check_nfs_root_squashing():
    """
    Parse nfs configuration /etc/exports to find no_root_squash directive
    """
    path = '/etc/exports'
    if os.path.exists(path):
        try:
            with open(path) as f:
                for line in f.readlines():
                    if line.startswith('#'):
                        continue

                    if 'no_root_squash' in line.decode():
                        return 'no_root_squash directive found'
        except Exception:
            pass

    return False


def get_capabilities():
    """
    List capabilities found on binaries stored on /sbin/
    """
    bins = []
    getcap = '/sbin/getcap'
    if os.path.exists(getcap):
        for path in ['/usr/bin/', '/usr/sbin/']:
            cmd = '{getcap} -r -v {path} | grep "="'.format(getcap=getcap, path=path)
            output, err = run_cmd(cmd)
            if output:
                for line in output.split('\n'):
                    if line.strip():
                        binary, capabilities = line.strip().split('=')
                        bins.append('%s: %s' % (binary, capabilities))

    if bins: 
        return tab_to_string(bins)

    return False


def get_exploits():
    """
    Run linux exploit suggester tool
    """
    if 'linux' in sys.platform:
        exploit = Exploit()
        output, err = run_cmd(exploit.code)
        if output.strip():
            return output


def check_python_library_hijacking(user):
    lib_path = []

    # Do not check current directory (it would be writable and no privilege escalation could be done)
    for path in sys.path[1:]:
        if getpass.getuser() not in path:
            f = File(path)
            if f.is_writable(user): 
                lib_path.append(path)
    return lib_path


def get_ptrace_scope():
    try:
        with open('/proc/sys/kernel/yama/ptrace_scope', 'rb') as f:
            ptrace_scope = int(f.read().strip())

        if ptrace_scope == 0:
            return 'PTRACE_ATTACH possible ! (yama/ptrace_scope == 0)'

    except IOError:
        pass


def check_sudoers_misconfigurations(file_info, services, suids, user, rules, already_impersonated=[], result=''):
    """
    Recursive function to analyse sudoers rules
    If a user could impersonate other users others paths using these users are checked
    file_info, services and suids are class to performs checks if user are impersonated
    """
    if rules:

        sudo = Sudo(user)
        paths_found = sudo.anaylyse_sudo_rules(rules)
        if paths_found:
            result += '### Rules for {user} ###\n\n'.format(user=user.pw_name)
            result += tab_of_dict_to_string(paths_found, new_line=False)

            # If this tab is not empty means that we are impersonating another user
            if already_impersonated:
                # Check for other misconfiguration path
                result += tab_of_dict_to_string(file_info.write_access_on_files(user))
                result += tab_of_dict_to_string(services.write_access_on_binpath(user))
                result += tab_of_dict_to_string(suids.check_suid_bins(
                    user),
                    new_line=False,
                    title=False,
                )
                result += tab_to_string(check_python_library_hijacking(user)),

            # Use recursively to realize same checks for impersonated users
            for impersonate in sudo.can_impersonate:
                if impersonate not in already_impersonated:
                    already_impersonated.append(impersonate)
                    result += check_sudoers_misconfigurations(impersonate, rules, already_impersonated, result)

    return result
