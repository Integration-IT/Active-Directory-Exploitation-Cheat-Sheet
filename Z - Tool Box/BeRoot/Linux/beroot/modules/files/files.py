#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import stat

from ..users import Users
from ..useful.useful import run_cmd


class File(object):
    """
    File properties
    alias: if binary are directly called inside files (ex: chmod +x ... => path = /bin/chmod and alias = chmod)
    """

    def __init__(self, path, alias=None):
        self.path = os.path.realpath(path)  # Follow symbolic link
        self.alias = alias
        self.basename = os.path.basename(self.path)
        self.dirname = os.path.dirname(self.path)
        self.permissions = self.get_permissions(self.path)
        self.is_not_ascii = self.check_if_not_ascii()

    def get_permissions(self, path):
        try:
            return os.stat(path)
        except Exception:
            return None

    def check_if_not_ascii(self):
        """
        This check is used to detect an executable/script file with or without x flag
        """
        cmd = 'file %s | cut -d " " -f 2 | grep -i ascii' % self.path
        output, err = run_cmd(cmd)
        if output:
            return False # is ascii
        else:
            return True

    def is_readable(self, user=Users().current):
        """
        Check read permission on a file for the current user
        https://docs.python.org/3/library/stat.html
        """
        uid = user.pw_uid
        gid = user.pw_gid
        if self.permissions:
            mode = self.permissions[stat.ST_MODE]
            return (
                    ((self.permissions[stat.ST_UID] == uid) and (mode & stat.S_IRUSR)) or  # Owner has write permission.
                    ((self.permissions[stat.ST_GID] == gid) and (mode & stat.S_IRGRP)) or  # Group has write permission.
                    (mode & stat.S_IROTH)  # Others have write permission.
            )
        # No permissions
        return 0

    # def is_suid(self, path):
    #     """
    #     Check if the file is SUID (not used, should be removed)
    #     """
    #     return True if (os.stat(path).st_mode & stat.S_ISUID) != 0 else False

    def is_writable(self, user=Users().current):
        """
        Check writable access to a file from a wanted user
        https://docs.python.org/3/library/stat.html
        """
        uid = user.pw_uid
        gid = user.pw_gid
        if self.permissions:
            mode = self.permissions[stat.ST_MODE]
            return (
                    ((self.permissions[stat.ST_UID] == uid) and (mode & stat.S_IWUSR)) or  # Owner has write permission.
                    ((self.permissions[stat.ST_GID] == gid) and (mode & stat.S_IWGRP)) or  # Group has write permission.
                    (mode & stat.S_IWOTH)  # Others have write permission.
            )
        # No permissions
        return 0
