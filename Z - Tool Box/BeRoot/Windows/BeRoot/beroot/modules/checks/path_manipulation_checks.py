# -*- coding: utf-8 -*-
import os
import ntpath
import re

from ..objects.path import Path


def is_root_dir_writable(path, is_dir=False):
    """
    Check the permission of an exe file
    """
    if is_dir:
        dirname = path
    else:
        dirname = ntpath.dirname(path)

    new_path = os.path.join(dirname, "a.txt")

    try:
        f = open(new_path, "w")
        f.close()
        os.remove(new_path)
        return True
    except Exception:
        return False


def get_sub_dir_writable(path):
    results = []
    path = os.path.dirname(path).split(os.sep)
    tmp_path = os.path.join(path[0], os.sep)
    for i in path[1:]:
        if " " in i and is_root_dir_writable(tmp_path, True):
            results.append(tmp_path)
        tmp_path = os.path.join(tmp_path, i)
    return results


# Global variable to not compile it every time
reg = r"(?P<fullpath>\"?[a-zA-Z]:(\\\w[ (?\w\.)?]*)+\.\w\w\w\"?)"
regex = re.compile(reg, re.IGNORECASE)


def get_path_info(path):
    paths = []
    path = os.path.expandvars(path)
    for res in regex.findall(path):
        has_quotes = False
        has_space = False
        path = res[0].strip()

        if ' ' in path:
            has_space = True

        if '\'' in path or '"' in path:
            has_quotes = True
            path = path.replace('\'', '').replace('"', '')

        paths.append(
            Path(
                path=path,
                has_space=has_space,
                has_quotes=has_quotes,
                is_dir_writable=is_root_dir_writable(path),
                sub_dir_writables=get_sub_dir_writable(path)
            )
        )

    return paths


def space_and_no_quotes(data):
    """
    Check path containing space without quotes
    """
    results = []
    for sk in data:
        for p in sk.paths:
            if p.has_space and not p.has_quotes and p.sub_dir_writables:
                results.append(format_results(sk, p, True))
    return results


def exe_with_writable_directory(data):
    """
    Check if the directory containing the exe is writable (useful for dll hijacking or to replace the exe if possible)
    """
    results = []
    for sk in data:
        for p in sk.paths:
            if p.is_dir_writable:
                results.append(format_results(sk, p))
    return results


def format_results(sk, p, check_subdir=False):
    """
    Format result into a tab
    """
    results = {}
    if 'key' in dir(sk):
        if sk.key:
            results['Key'] = sk.key

    if 'permissions' in dir(sk):
        if sk.permissions:
            results['permissions'] = str(sk.permissions)

    if 'runlevel' in dir(sk):
        if sk.runlevel:
            results['Runlevel'] = sk.runlevel

    if 'userid' in dir(sk):
        if sk.userid:
            results['UserId'] = sk.userid

    results['Name'] = sk.name
    results['Full path'] = sk.full_path

    if not check_subdir:
        results['Writable directory'] = os.path.dirname(p.path)
    else:
        results['Writable paths found'] = []
        for d in p.sub_dir_writables:
            results['Writable paths found'].append(d)

    return results
