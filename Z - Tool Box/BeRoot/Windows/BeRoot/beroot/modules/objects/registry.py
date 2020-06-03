# -*- coding: utf-8 -*-


class RegistryKey(object):
    def __init__(self):
        self.key = None
        self.name = None
        self.is_key_writable = False
        self.display_name = None
        self.full_path = None
        self.paths = []
