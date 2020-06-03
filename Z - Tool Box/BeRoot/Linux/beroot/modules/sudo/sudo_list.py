#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import random
import re
import string
import tempfile
import traceback

from ..files.file_manager import FileManager
from ..files.path_in_file import PathInFile
from ..users import Users
from ..useful.useful import run_cmd


class SudoList(object):
    """
    Get rules and parse output from sudo -ll output
    """

    def __init__(self, password='test'):
        self.sudo_cmd = 'echo "{password}" | sudo -S -ll'.format(password=password)
        self.sudo_dirty_check = [
            'echo "{password}" | sudo -S -i'.format(password=password),
            # 'sudo -i'
        ]
        self.users = Users()
        self.all_rules = []
        self.ld_preload = False

    def dirty_check(self):
        for cmd in self.sudo_dirty_check:
            if run_cmd(cmd, is_ok=True):
                return 'sudo -i possible !'

    def _get_user(self, user):
        """
        Find a user pw object from his name
        - user is a string
        - u is an object
        """
        for u in self.users.list:
            if u.pw_name == user:
                return u
        return False

    def rules_from_sudo_ll(self):
        """
        Main function to retrieve sudoers rules from sudo -ll output
        """
        sudo_list, _ = run_cmd(self.sudo_cmd)
        if sudo_list:
            sudo_rules = self._parse_sudo_list(sudo_list)
            self._impersonate_mechanism(self.users.current.pw_name, sudo_rules, users_chain=[])

        return self.all_rules

    def _parse_sudo_list(self, sudo_list):
        """
        Parse sudo -ll output
        """
        sudoers_info = []
        fm = FileManager('')
        
        if 'LD_PRELOAD' in sudo_list:
            self.ld_preload = True

        user = sudo_list[sudo_list.index('User '):].split(' ')[1]
        sudoers_entries = sudo_list.lower().split('sudoers entry')
        for sudo_rule in sudoers_entries:

            if not sudo_rule.startswith(':'):
                continue

            pattern = re.compile(
                r"\s*" +
                "runasusers:\s*(?P<runasusers>\w*)" +
                "\s*" +
                "(runasgroups:\s*(?P<runasgroups>\w*))*" +
                "\s*" +
                "(options:\s*(?P<options>[\!\w]*))*" +
                "\s*" +
                "(commands:\s*(?P<commands>.*))*",
                re.DOTALL
            )
            m = pattern.search(sudo_rule)
            # Default to empty string '' for values we didn't match
            data = m.groupdict('')
            # Remove whitespace and extra tabs from list of commands
            cmds = [PathInFile(line=cmd.strip(), paths=fm.extract_paths_from_string(cmd.strip()))
                    for cmd in data['commands'].strip().replace('\t', '').split('\n')]

            sudoers_info.append({
                'users': [user],
                'runas': data['runasusers'],
                'directives': data['options'],
                'cmds': cmds,
            })

        self.all_rules += sudoers_info
        return sudoers_info

    def _get_user_to_impersonate(self, sudo_rules):
        """
        Check if in the sudo rule, user impersonation is possible (using su bin)
        """
        users = []
        for rules in sudo_rules:
            for cmd in rules['cmds']:
                for c in cmd.paths:
                    if c.basename == 'su':
                        # Do not perform further checks as it's already to impersonate root user
                        args = cmd.line.strip()[cmd.line.strip().index(c.basename) + len(c.basename):].strip()
                        if args.strip() and args.strip() not in ['root', '*']:
                            u = self._get_user(args.strip())
                            if u:
                                users.append(u)
        return users

    def _impersonate_user(self, users_chain=[]):
        """
        Get the user to impersonate and return his sudo -l output

        For example:
        - The current user has "su" rule to impersonate user A
        - The user A can impersonate user B (but the current user cannot)
        - User B has root privilege
        => users_chain = ["user A", "user B"]

        sudo -l return only rules concerning the user launching this command. 
        
        The trick is to use a temporary file like following: 
        sudo su test << 'EOF'         
        echo "test" | sudo -S -l
        EOF
        """
        data = ''
        for u in users_chain:
            data += "sudo su {user} << 'EOF'\n".format(user=u)
        data += self.sudo_cmd + '\n'
        
        if users_chain: 
            data += '\nEOF'

        rand = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
        path = os.path.join(tempfile.gettempdir(), rand) + '.sh'
        with open(path, 'w') as file:
            file.write(data)

        if os.path.exists(path):
            out = run_cmd(cmd='chmod +x {path}'.format(path=path), is_ok=True)
            if out:
                out, _ = run_cmd(cmd=path)
            os.remove(path)
            return out

    def _impersonate_mechanism(self, user, sudo_rules, users_chain=[], already_impersonated=[]):
        """
        Recursive function to retrieve all sudo rules
        All rules for all possible users are stored on "all_rules"
        """
        for u in self._get_user_to_impersonate(sudo_rules):
            if u not in already_impersonated:
                sudo_list = self._impersonate_user(users_chain=[user, u])
                if sudo_list:
                    try:
                        sudo_rules = self._parse_sudo_list(sudo_list)
                        self._impersonate_mechanism(u, sudo_rules, [user, u], already_impersonated)
                    except Exception:
                        print(traceback.format_exc())
                        continue

                    already_impersonated.append(u)
