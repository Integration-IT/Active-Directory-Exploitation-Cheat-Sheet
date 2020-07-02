#!/usr/bin/python
# -*- coding: utf-8 -*-
from beroot.run import check_all, get_sofwares
import argparse
import time
import traceback
import os


def print_output(output):
    st = '\n################ {category} ################\n'.format(category=output['category'])
    if output.get('error'):
        st += output.get('error')
    else: 
        for desc, result in output.get('results'):
            if result:
                st += '\n# %s\n'% desc
                st += '%s\n' % result

    print(str(st))


def run_check_all(list_softwares):
    # Realize all classic checks
    f = check_all
    # Retrieve all softwares installed
    if list_softwares: 
        f = get_sofwares

    for r in f():
        yield r


if __name__ == '__main__':
    banner = '|====================================================================|\n'
    banner += '|                                                                    |\n'
    banner += '|                    Windows Privilege Escalation                    |\n'
    banner += '|                                                                    |\n'
    banner += '|                          ! BANG BANG !                             |\n'
    banner += '|                                                                    |\n'
    banner += '|====================================================================|\n\n'

    print(banner)

    parser = argparse.ArgumentParser(description="Windows Privilege Escalation")
    parser.add_argument("-l", "--list", action="store_true", help="list all softwares installed (not run by default)")
    args = parser.parse_args()

    start_time = time.time()
    for r in run_check_all(args.list):
        try:
            print_output(r)
        except Exception:
            # Manage unicode
            print(traceback.format_exc())

    elapsed_time = time.time() - start_time
    print('\n[!] Elapsed time = ' + str(elapsed_time))
