#!/usr/bin/env python
# -*- coding: utf-8 -*-
import grp
import os
import pwd


class Users:
    """
    Get users list with uid and gid
    """
    def __init__(self):
        self.list = pwd.getpwall()
        self.current = [p for p in self.list if p.pw_uid == os.getuid()][0]
        self.groups = grp
