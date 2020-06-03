#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import traceback

from ..files.file_manager import FileManager
from ..files.path_in_file import PathInFile
from ..files.files import File


class SudoersFile(object):
    """
    Get rules and parse output from sudoers file (/etc/sudoers) 
    """
    def __init__(self):
        self.sudoers_pattern = re.compile(r"(\( ?(?P<runas>.*) ?\)) ?(?P<directives>(\w+: ?)*)(?P<cmds>.*)")
        self.sudoers_file = '/etc/sudoers'
        self.sudoers_dir = '/etc/sudoers.d/'
        self.ld_preload = False

    def rules_from_sudoers_file(self):
        """
        Main function to retrieve sudoers rules from /etc/sudoers file
        Get content from /etc/sudoers
        Concatenate will all rules found on /etc/sudoers.d/ directory
        """
        content = ''
        f = File(self.sudoers_file)
        if f.is_readable():
            content += open(self.sudoers_file).read()

            if os.path.exists(self.sudoers_dir):
                for file in os.listdir(self.sudoers_dir): 
                    try:
                        content += open(os.path.join(self.sudoers_dir, file)).read()
                    except Exception:
                        pass

            if content: 
                return self._parse_sudoers(content)

    def _manage_alias(self, kind_alias, data, alias_name):
        """
        Replace the value with the alias if an alias exists
        ex:
        - User_Alias ADMINS = admin, test, root
        - user,ADMINS ALL = (ALL) su root => users tab will be considered as ['user', 'admin', 'test', 'root']
        """
        if data:
            for alias in kind_alias[alias_name]:
                if alias in data:
                    return [d.strip() for d in data.split(',') if d != alias] + kind_alias[alias_name][alias]

            # No alias found, return the result as tab
            return [d.strip() for d in data.split(',')]

    def _parse_sudoers(self, content):
        """
        Parse sudoers file to check write permissions on all files with the NOPASSWD directive
        """
        fm = FileManager('')
        alias = []
        sudoers_rules = []
        tmp_line = ''
        kind_alias = {
            'User_Alias': {},
            'Runas_Alias': {},
            'Host_Alias': {},
            'Cmnd_Alias': {},
        }

        for line in content.split('\n'):
            # Empty or comment line
            if line.startswith('#') or not line.strip():
                continue

            # On "defaults" directive only check for env_keep
            if line.startswith('Defaults'):
                if 'env_keep' in line and 'LD_PRELOAD' in line:
                    self.ld_preload = True
                continue

            # Manage when lines are written in multiple lines (lines ending with "\"")
            if line.strip().endswith('\\'):
                tmp_line += line.strip()[:-1]
                continue
            else:
                if tmp_line:
                    line = tmp_line + line.strip()
                    tmp_line = ''

            # ----- Manage all kind of alias -----

            alias_line = False
            for alias in kind_alias:
                if line.startswith(alias):
                    for l in line.split(':'):
                        alias_name, alias_cmd = l.split('=')
                        alias_name = alias_name.replace(alias, '').strip()

                        if alias_name in kind_alias[alias]:
                            kind_alias[alias][alias_name] += [a.strip() for a in alias_cmd.split(',')]
                        else:
                            kind_alias[alias][alias_name] = [a.strip() for a in alias_cmd.split(',')]
                        alias_line = True
                    break

            if alias_line:
                continue

            # ----- End of Alias -----

            # Basic command pattern: "users  hosts = (run-as) directive: commands"
            try:
                owner, cmds = line.strip().split('=')
                users, hosts = owner.split()

                m = self.sudoers_pattern.search(cmds.strip())
                if not m:
                    continue

                runas = m.group("runas")
                cmds = m.group("cmds")
                sudoers_rules.append(
                    {
                        'users': self._manage_alias(kind_alias, users, 'User_Alias'),
                        'hosts': self._manage_alias(kind_alias, hosts, 'Host_Alias'),
                        'runas': self._manage_alias(kind_alias, runas, 'Runas_Alias'),
                        'directives': m.group("directives"),
                        # Could be a list of many cmds with many path (split all cmd and check if writable path inside)
                        'cmds': [
                                    PathInFile(
                                        line=cmd.strip(), 
                                        paths=fm.extract_paths_from_string(cmd.strip())
                                    ) for cmd in cmds.split(',') if cmd.strip()
                        ],
                        'line': line.strip(),
                    }
                )
            except Exception:
                print(traceback.format_exc())

        return sudoers_rules
