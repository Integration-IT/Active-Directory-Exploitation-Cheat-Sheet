#!/usr/bin/env python
# -*- coding: utf-8 -*-
import subprocess


def tab_of_dict_to_string(tab, new_line=True, title=True):
    """
    Convert a tab of dic to a string
    """
    string = ''
    for values in tab:
        to_end = ''
        for value in values:
            # list output always written at end
            if 'list' in str(type(values[value])):
                to_end += '%s:\n' % str(value)
                for w in values[value]:
                    if w.strip():
                        to_end += '\t- %s\n' % w.strip()
            else:
                if title:
                    string += '%s: %s\n' % (value, str(values[value]))
                else:
                    string += '%s\n' % values[value]
        string += to_end
        if new_line:
            string += '\n'
    return string


def tab_to_string(tab):
    """
    Convert a tab of string into a string
    """
    string = ''
    for value in tab:
        string += '%s\n' % value
    return string


def bool_to_string(value):
    """
    Convert a bool to a string
    """
    return str(value)


def run_cmd(cmd, is_ok=False):
    """
    Run cmd
    """
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                         shell=True, executable='/bin/bash')

    output, err = p.communicate()
    if is_ok:
        if p.returncode == 0:
            return True
        else:
            return False

    return output, err

