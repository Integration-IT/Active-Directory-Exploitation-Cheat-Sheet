# -*- coding: utf-8 -*-
from ..objects.winstructures import get_currents_privs

def check_currrent_user_privilege():
    """
    Check if our user has interesting tokens
    """
    # Interesting Windows Privileges
    # - SeDebug
    # - SeRestore
    # - SeBackup
    # - SeTakeOwnership
    # - SeTcb
    # - SeCreateToken
    # - SeLoadDriver
    # - SeImpersonate
    # - SeAssignPrimaryToken

    interesting_priv = (
        u'SeDebug', u'SeRestore', u'SeBackup', u'SeTakeOwnership', 
        u'SeTcb', u'SeCreateToken', u'SeLoadDriver', u'SeImpersonate', 
        u'SeAssignPrimaryToken'
    )
    privs = get_currents_privs()
    priv = []

    for (privilege, enabled) in privs:
        if enabled:
            string = privilege
            for p in interesting_priv:
                if p in privilege:
                    string += '  => Could be used to elevate our privilege'
                    break
            priv.append(string)

    return priv