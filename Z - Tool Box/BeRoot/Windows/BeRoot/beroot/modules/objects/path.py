# -*- coding: utf-8 -*-


class Path(object):
    def __init__(self, path=None, has_space=None, has_quotes=False, is_dir_writable=False, sub_dir_writables=[]):
        self.path = path
        self.has_space = has_space
        self.has_quotes = has_quotes
        self.is_dir_writable = is_dir_writable
        self.sub_dir_writables = sub_dir_writables
