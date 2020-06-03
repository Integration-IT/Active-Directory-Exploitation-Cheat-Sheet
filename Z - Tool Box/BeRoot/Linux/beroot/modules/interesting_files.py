# -*- coding: utf-8 -*-
import os

from .files.file_manager import FileManager
from .files.files import File


class InterestingFiles(object):
    """
    Interesting files
    """
    def __init__(self):

        self.files = [
            # directories
            '/etc/init.d'
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.monthly',
            '/etc/cron.weekly',
            '/etc/ld.so.conf',

            # files
            '/etc/sudoers',
            '/etc/passwd',
            '/etc/shadow',
            '/etc/exports',
            '/etc/at.allow',
            '/etc/at.deny',
            '/etc/crontab',
            '/etc/cron.allow',
            '/etc/cron.deny',
            '/etc/anacrontab',
            '/etc/apache2/apache2.conf',
            '/var/spool/cron/crontabs/root',
        ]
        print('Getting permissions of sensitive files. Could take some time...')
        self.properties = self._get_permissions(self.files)

    def _get_permissions(self, paths):
        """
        paths contains a tab of string
        return a tab of FileManager object
        """
        properties = []
        for path in paths:

            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        fullpath = os.path.join(root, file)
                        fm = FileManager(fullpath, check_inside=True)
                        properties.append(fm)

            else:
                fm = FileManager(path, check_inside=True)
                properties.append(fm)

        return properties

    def write_access_on_subfiles(self, f_info, user):
        has_write_access = []
        for subfiles in f_info.subfiles:
            for subfile in subfiles.paths:
                dir_writable = ''

                # Should be an executable (check if dirname is writable)
                if subfile.is_not_ascii:
                    f = File(subfile.dirname)
                    if f.is_writable(user):
                        dir_writable = '\n\t\t- directory: %s [writable]' % subfile.dirname

                if subfile.is_writable(user) and not subfiles.line.startswith('#'):
                    has_write_access.append(
                        '[writable: %s] => %s%s' % (subfile.path, subfiles.line, dir_writable)
                    )
        return has_write_access

    def write_access_on_files(self, user):
        has_write_access = []
        for p in self.properties: 
            perm = ''
            values = {}
            dir_writable = False 

            if p.file.is_writable(user):
                perm = '[writable]'

            subfiles = []
            if p.file.is_readable(user):
                subfiles = self.write_access_on_subfiles(p, user)

            # Should be an executable (check if dirname is writable)
            if p.file.is_not_ascii:
                f = File(p.file.dirname)
                if f.is_writable(user):
                    dir_writable = True

            if subfiles or perm or dir_writable:
                values = {
                    'path': '%s %s' % (p.file.path, perm)
                }

                if subfiles: 
                    values['subfiles'] = subfiles

                if dir_writable:
                    if subfiles: 
                        values['directory'] = '%s [writable]' % p.file.dirname

            if values: 
                has_write_access.append(values)

        # Check if /usr/lib and /lib are writable without looking inside (too long)
        for directory in ['/usr/lib', '/lib']:
            f = File(directory)
            if f.is_writable(user):
                has_write_access.append({
                    'path': '%s [writable]' % directory
                })

        return has_write_access
