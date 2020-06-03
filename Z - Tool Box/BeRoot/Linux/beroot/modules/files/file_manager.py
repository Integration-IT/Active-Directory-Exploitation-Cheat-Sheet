#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import os

from .files import File
from .path_in_file import PathInFile


class FileManager(object):
    """
    This object contains File object
    File content can be checked if check_inside=True
    If so, other paths are extracted and stored in a tab (subfiles) of PathInFile
    The main goal of PathInFile is to keep stored the entire line called
    """

    def __init__(self, path='', check_inside=False):
        self.file = File(path)
        self.path_pattern = re.compile(r"^[\'\"]?(?:/[^/]+)*[\'\"]?$")
        self.subfiles = []  # Tab of PathInFile object
        if self.file.is_readable() and check_inside:
            self.subfiles = self.parse_file(path)

    def extract_paths_from_string(self, string):
        """
        Extract paths from string and check if we have write access on it
        """
        paths = []
        blacklist = ['/dev/null', '/var/crash']  # Remove false positive
        built_in = ['/bin', '/usr/bin/', '/sbin', '/usr/sbin']
        string = string.replace(',', ' ')

        # Split line to manage multiple path on a line - will not work for path containing quotes and a space
        for path in string.strip().split():
            m = self.path_pattern.search(path.strip())
            if m and m.group():
                file_path = m.group().strip()
                if os.path.exists(file_path) and os.path.realpath(file_path) not in blacklist:
                    paths.append(
                        File(file_path)
                    )

            # If the regex does not match a path, it could be a built-in binary inside /bin or /usr/bin
            else:
                for b in built_in:
                    file_path = os.path.join(b, path)
                    if os.path.exists(file_path) and file_path not in ['/', '.']:  # Remove false positive
                        paths.append(
                            File(file_path, alias=path)
                        )
                        break
        return paths

    def parse_file(self, path):
        """
        Try to find paths inside a file using regex
        """
        result = []
        try:
            with open(path) as f:
                for line in f.readlines():
                    paths = self.extract_paths_from_string(line.strip())
                    if paths:
                        result.append(
                            PathInFile(line=line.strip(), paths=paths)
                        )
        except Exception:
            pass

        return result
