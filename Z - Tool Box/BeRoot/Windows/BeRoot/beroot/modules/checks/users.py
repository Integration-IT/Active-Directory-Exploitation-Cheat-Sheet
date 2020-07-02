# -*- coding: utf-8 -*-
from ..objects.winstructures import try_empty_login


def check_empty_passwords(u):
    '''
    Local users have empty password
    '''
    empty_pwd = []
    for user in u.users:
        if try_empty_login(user['name']):
            empty_pwd.append(user['name'])

    return empty_pwd


def check_passwordreq_option(u):
    '''
    Check if password is not required
    if the user has been created with the option /passwordreq:no
    '''
    password_not_req = []
    for user in u.users:
        # Check if password is not required
        
        if not user['password_required']:
            password_not_req.append(user['name'])

    return password_not_req