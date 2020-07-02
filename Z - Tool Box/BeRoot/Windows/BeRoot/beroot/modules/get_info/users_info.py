# -*- coding: utf-8 -*-
from ..objects.winstructures import GetUserName, to_unicode, try_empty_login
import win32net


class Users(object):
    def __init__(self):
        self.users = self.users_info()

    def users_info(self):
        result = []
        users, _, _ = win32net.NetUserEnum(None, 3)
        current = GetUserName()

        UF_ACCOUNT_DISABLE = 2
        UF_LOCKOUT = 16
        PASSWD_NOTREQD = 32

        for user in users:
            # Remove all uninteresting accounts 
            if user['flags'] & (UF_ACCOUNT_DISABLE | UF_LOCKOUT) or user['name'] == current:
                continue

            # Check if password is required
            passwd_req = True
            if user['flags'] & PASSWD_NOTREQD:
                passwd_req = False

            # print win32net.NetUserGetInfo(None, user['name'], 1)
            result.append({
                'name': to_unicode(user['name']),
                'groups': [
                    to_unicode(x) for x in win32net.NetUserGetLocalGroups(None, user['name'])
                ],
                'admin': user['priv'] == 2,
                'password_required': passwd_req,
                'home': (
                    to_unicode(user['logon_server']) + u'\\' + to_unicode(user['home_dir'])
                ) if user['home_dir'] else u'default'
            })

        return result
