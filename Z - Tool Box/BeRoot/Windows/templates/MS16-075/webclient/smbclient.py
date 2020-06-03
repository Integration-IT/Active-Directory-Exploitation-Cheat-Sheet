# -*- coding: utf-8 -*-
from impacket.smb import NewSMBPacket, SMBCommand, SMB, SMBSessionSetupAndX_Data, SMBSessionSetupAndX_Extended_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Parameters, SMBSessionSetupAndX_Extended_Parameters, TypesMech

from impacket.ntlm import NTLMAuthChallengeResponse, NTLMAuthChallenge, AV_PAIRS, \
    NTLMSSP_AV_HOSTNAME, generateEncryptedSessionKey

from impacket.spnego import SPNEGO_NegTokenResp, SPNEGO_NegTokenInit


class SMBClient(SMB):
    def __init__(self, remote_name, extended_security=True, sess_port=445):
        SMB.__init__(self, remote_name, remote_name, sess_port=sess_port)

    def sendAuth(self, serverChallenge, authenticateMessageBlob):
        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired:
            smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
        smb['Uid'] = self._uid

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data'] = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize'] = 65535
        sessionSetup['Parameters']['MaxMpxCount'] = 2
        sessionSetup['Parameters']['VcNumber'] = 1
        sessionSetup['Parameters']['SessionKey'] = 0
        sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS'] = 'Unix'
        sessionSetup['Data']['NativeLanMan'] = 'Samba'

        sessionSetup['Parameters']['SecurityBlobLength'] = len(authenticateMessageBlob)
        sessionSetup['Data']['SecurityBlob'] = str(authenticateMessageBlob)
        smb.addCommand(sessionSetup)
        self.sendSMB(smb)

        smb = self.recvSMB()
        errorCode = smb['ErrorCode'] << 16
        errorCode += smb['_reserved'] << 8
        errorCode += smb['ErrorClass']

        # if errorCode == STATUS_SUCCESS: # and self._SignatureRequired is True and self.domainIp is not None:
        # 	try:
        # 		errorCode = self.netlogonSessionKey(serverChallenge, authenticateMessageBlob)
        # 	except:
        # 		#import traceback
        # 		#print(traceback.print_exc())
        # 		raise
        return smb, errorCode

    def sendNegotiate(self, negotiateMessage):
        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired:
            smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data'] = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize'] = 65535
        sessionSetup['Parameters']['MaxMpxCount'] = 2
        sessionSetup['Parameters']['VcNumber'] = 1
        sessionSetup['Parameters']['SessionKey'] = 0
        sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        blob['MechToken'] = str(negotiateMessage)

        sessionSetup['Parameters']['SecurityBlobLength'] = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob'] = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS'] = 'Unix'
        sessionSetup['Data']['NativeLanMan'] = 'Samba'

        smb.addCommand(sessionSetup)
        self.sendSMB(smb)
        smb = self.recvSMB()

        try:
            smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
        except Exception:
            print("SessionSetup Error!")
            raise
        else:
            # We will need to use this uid field for all future requests/responses
            self._uid = smb['Uid']

            # Now we have to extract the blob to continue the auth process
            sessionResponse = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData = SMBSessionSetupAndX_Extended_Response_Data(flags=smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            return respToken['ResponseToken']
