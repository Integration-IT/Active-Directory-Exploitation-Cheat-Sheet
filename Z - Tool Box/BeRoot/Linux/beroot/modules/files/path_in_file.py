#!/usr/bin/env python
# -*- coding: utf-8 -*-


class PathInFile(object):
    """
    Path found inside configuration files (such as crons, services, etc.)
    """
    def __init__(self, line, paths=[]):
        self.line = line
        self.paths = paths  # Tab of File object
