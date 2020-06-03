#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ..gtfobins import GTFOBins
from ..users import Users


class Sudo(object):
    """
    Contain all checks done on sudo configuration
    """
    def __init__(self, user):
        self.all_rules = []
        self.users = Users()
        self.gtfobins = GTFOBins()
        self.user = user
        self.can_impersonate = []

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

    def anaylyse_sudo_rules(self, sudo_rules):
        """
        sudo_rules is a dictionary containing all rules found on the sudoers file or from sudo -ll
        user is an object containing the current user properties
        """

        # Get associated groups for the current user
        user_groups = [g.gr_name for g in self.users.groups.getgrall() if self.user.pw_name in g.gr_mem]
        results = []

        for rules in sudo_rules:

            # need_password = True
            # # NOPASSWD present means that no password is required to execute the commands
            # if 'NOPASSWD' in rules['directives'] or '!authenticate' in rules['directives']:
            #     need_password = False

            # Check if the rule affects the current user or his group
            rule_ok = False
            for user_or_group in rules['users']:
                if (user_or_group.startswith('%') and user_or_group[1:] in user_groups) \
                        or (self.user.pw_name == user_or_group):
                    rule_ok = True

            if not rule_ok:
                continue

            for cmd in rules['cmds']:

                # Action denied, continue
                if cmd.line.startswith('!'):
                    continue
                
                # All access
                if cmd.line.lower().strip() == 'all':
                    results.append({
                        'rule': rules.get('line', cmd.line),
                        'ALL': 'all permissions'
                    })

                # All cmds available by the rule
                for c in cmd.paths:

                    # Check write access on a file or for a gtfobin 
                    write_access = c.is_writable(self.user)
                    shell_escape = self.gtfobins.find_binary(c.basename)
                    
                    if write_access or shell_escape:
                        result = {'rule': rules.get('line', cmd.line)}
                        if write_access:
                            result['path'] = '%s [writable]' % c.path
                        if shell_escape: 
                            result['gtfobins found (%s)' % c.basename] = shell_escape.split('\n')

                        results.append(result)

                    # check if user impersonation is possible
                    if c.basename == 'su':                        
                        args = cmd.line.strip()[cmd.line.strip().index(c.basename) + len(c.basename):].strip()

                        results.append({
                            'rule': rules.get('line', cmd.line),
                            'impersonate': args
                        })

                        # Do not perform further checks as it's already to impersonate root user
                        if args.strip() and args.strip() not in ['root', '*']:
                            # User to impersonate not found on the filesystems
                            u = self._get_user(args.strip())
                            if u:
                                self.can_impersonate.append(u)

        return results
