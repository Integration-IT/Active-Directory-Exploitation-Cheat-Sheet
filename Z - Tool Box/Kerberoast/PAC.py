#!/usr/local/bin/python2 -tt

import struct
import collections
from abc import ABCMeta, abstractmethod
#from datetime import datetime,timedelta
import datetime
import math

def BytesToTime(b):
	# The FILETIME structure is a 64-bit value that represents the number of 
	# 100-nanosecond intervals that have elapsed since January 1, 1601 (UTC).
	mftime = struct.unpack('<Q', b)[0]	
	if mftime == 0x7fffffffffffffff:
		return None
	else:
		microseconds = struct.unpack('<Q', b)[0] / 10.0
		nanoseconds = (struct.unpack('<Q', b)[0] % 10000000) * 100
		
		dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

		dtn  = datetimenano(dt, nanosecond=nanoseconds)

		return dtn

def TimeToBytes(time):
	if time == None:
		return '\xff\xff\xff\xff\xff\xff\xff\x7f' # 0x7fffffffffffffff LE
	else:
		td = time - datetime.datetime(1601,1,1)
		#seconds = math.floor(td.total_seconds())
		hundredsofnano = long(math.floor(td.total_seconds()) * 10000000)

		if hasattr(time, 'nanosecond'):
			hundredsofnano += long(time.nanosecond / 100)
		else:
			hundredsofnano += long(time.microseconds * 10)

		return struct.pack('<Q', hundredsofnano)

		'''
		if hasattr(time, 'nanosecond'):
			#microseconds = ((td.total_seconds() * 1000000) + td.microseconds)
			#replace microseconds for nanoseconds
			#microseconds = microseconds - time.microsecond
			#nanoseconds = microseconds * 1000 + time.nanoseconds
			nanoseconds = ((td.total_seconds() * 1000000000) + time.nanosecond)

			print 'seconds     %i' % (math.floor(td.total_seconds()))
			print 'nanoseconds %i' % time.nanosecond

			return struct.pack('<Q', nanoseconds)
			hundredsofnano = nanoseconds / 100
		else:
			#microseconds = ((td.total_seconds() * 1000000) + td.microseconds) * 10
			microseconds = ((td.total_seconds() * 1000000) + td.microseconds)
			hundredsofnano = microseconds * 10
		print '%15f' % hundredsofnano
		return struct.pack('<Q', hundredsofnano)
		'''

def PrettyTime(time):
	if time == None:
		return 'Infinity'
	else:
		return str(time)

def AlignedString(s, alignment = 4):
	return s + '\x00' * ((alignment - (len(s) % alignment)) % alignment)


class datetimenano(datetime.datetime):
	def __new__(cls, *args, **kwargs):
		if len(args) > 0 and type(args[0]) == datetime.datetime:
			dt = args[0]

			#dt = datetime.datetime.__new__(cls, dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond, dt.tzinfo)
			if 'nanosecond' in kwargs:
				#setattr(dt, 'nanoseconds', args[0].tzinfo)
				dt = datetime.datetime.__new__(cls, dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond, dt.tzinfo)
				setattr(dt, 'nanosecond', kwargs['nanosecond'])
			else:
				#setattr(dt, 'nanoseconds', 0)
				dt = datetime.datetime.__new__(cls, dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond, dt.tzinfo, nanoseconds=0)
				setattr(dt, 'nanosecond', 0)
			return dt
		else:
			dt = super(datetimenano, cls).__new__(cls, *args[:8], **kwargs)
			if len(args) == 9:
				setattr(cls, 'nanosecond', args[8])
			else:
				setattr(cls, 'nanosecond', 0)
			return dt			

	def __str__(self):
		s = super(datetimenano, self).__str__()
		return '%s.%09i' % (s.split('.')[0], self.nanosecond)
		return s

class PacInfoStructure(object):
	__metaclass__ = ABCMeta

	PrettyName = 'PacInfoStructure'

	Type = None
	PrettyName = None
	BufferSize = None
	Offset = None
	Data = None


	def __init__(self, pac, index=0):
		if input != None:
			offset = 8 + 16 * index

			self.Type, self.BufferSize, self.Offset = struct.unpack('<III', pac[offset:offset+12])
			self.Data = pac[self.Offset:self.Offset+self.BufferSize]

	def __str__(self):
		return '%s (%i) Size: %i  Offset: %i\nData: %s' % (self.PrettyName, self.Type, self.BufferSize, self.Offset, self.Data.encode('hex'))

	#def encode(self):
	#	e = str(struct.pack('<III', self.Type, self.BufferSize, self.Offset)) + self.encode()
	#	return e

	#@abstractmethod
	def encode(self):
		return self.Data

class PacLoginInfo(PacInfoStructure):
	Version = None
	ByteOrder = None
	HeaderLen = None
	FillBytes = None
	InitialLength = None

	Type = 1
	PrettyName = 'Login Info'
	#ReferentID = None
	LogonTime = None
	KickoffTime = None
	PwdLastSet = None
	PwdCanChange = None
	PwdMustChange = None

	Logoncount = None
	BadpPasswordCount = None
	UserRid = None
	GroupRid = None
	
	AccountName = None
	DisplayName = None
	LogonScript = None
	ProfilePath = None
	HomeDir = None
	DirDrive = None



	#LogonCount

	class Referent(object):
		Length = None
		Size = None
		ReferentID = None
		Groups = []

		def __init__(self, data):
			self.Length = struct.unpack('<H', data[0:2])[0]
			self.Size = struct.unpack('<H', data[2:4])[0]
			self.ReferentID = struct.unpack('<L', data[4:8])[0]

		def __str__(self):
			return 'Length: %i  Size: %i  ReferentID: 0x%08x' % (self.Length, self.Size, self.ReferentID)

		@property
		def PaddLen(self):
			# must bye 4 byte aligned
			return (4 - (self.Length % 4)) % 4

	def __init__(self, pac, index=0):
		super(self.__class__, self).__init__(pac, index)
		if self.Type != 1:
			raise ValueError('PAC Information Structure is not Login Info')

		#self.MesHeader = self.Data[0:16]
		#MessageHeader
		self.Version, self.ByteOrder, self.HeaderLen = struct.unpack('<BBH', self.Data[0:4])
		self.FillBytes = self.Data[4:8]
		self.InitialLength = struct.unpack('<Q', self.Data[8:16])[0]


		#self.ReferentD = self.Data[16:20]

		self.LogonTime = BytesToTime(self.Data[20:28])
		#print 'Logon Time: %s' % PrettyTime(self.LogonTime)
		self.LogoffTime = BytesToTime(self.Data[28:36])
		#print 'Logoff Time: %s' % PrettyTime(self.LogoffTime)
		self.KickoffTime = BytesToTime(self.Data[36:44])
		#print 'Kickoff Time: %s' % PrettyTime(self.KickoffTime)
		self.PwdLastSet = BytesToTime(self.Data[44:52])
		#print 'PwdLastSet Time: %s' % PrettyTime(self.PwdLastSet)
		self.PwdCanChange = BytesToTime(self.Data[52:60])
		#print 'PwdCanChange Time: %s' % PrettyTime(self.PwdCanChange)
		self.PwdMustChange = BytesToTime(self.Data[60:68])
		#print 'PwdMustChange Time: %s' % PrettyTime(self.PwdMustChange)

		accountnameref = self.Referent(self.Data[68:76])
		# print 'accountnameref %s' % accountnameref
		fullnameref = self.Referent(self.Data[76:84])
		#print fullnameref
		logonscriptref = self.Referent(self.Data[84:92])
		#print logonscriptref
		profilepathref = self.Referent(self.Data[92:100])
		#print profilepathref
		homedirref = self.Referent(self.Data[100:108])
		#print homedirref
		dirdriveref = self.Referent(self.Data[108:116])
		#print dirdriveref
		self.Logoncount, self.BadpPasswordCount, self.UserRid, self.GroupRid, numrids = struct.unpack('<HHLLL', self.Data[116:132]) #[0]

		DATAOFFSET = 236

		# TODO: Decode and re-encode this
		self.extrajunk = self.Data[132:DATAOFFSET]

					
		offset = DATAOFFSET # points to first data item
		offset += 4 * 3 # max count, offset, actual count
		self.AccountName = self.Data[offset:offset+accountnameref.Length]#.decode('utf-8')
		#print '%i %s' % (offset, self.AccountName)
		offset += accountnameref.Length + accountnameref.PaddLen

		offset += 4 * 3 # max count, offset, actual count
		self.DisplayName = self.Data[offset:offset+fullnameref.Length]#.decode('utf-8')
		#print '%i %s' % (offset, self.DisplayName)
		offset += fullnameref.Length + fullnameref.PaddLen

		offset += 4 * 3 # max count, offset, actual count
		self.LogonScript = self.Data[offset:offset+logonscriptref.Length]
		#print '%i %s' % (offset, self.LogonScript)
		offset += logonscriptref.Length + logonscriptref.PaddLen

		offset += 4 * 3 # max count, offset, actual count
		self.ProfilePath = self.Data[offset:offset+profilepathref.Length]
		#print '%i %s' % (offset, self.ProfilePath)
		offset += profilepathref.Length + logonscriptref.PaddLen

		offset += 4 * 3 # max count, offset, actual count
		self.HomeDir = self.Data[offset:offset+homedirref.Length]
		#print '%i %s' % (offset, self.HomeDir)
		offset += homedirref.Length + homedirref.PaddLen

		offset += 4 * 3 # max count, offset, actual count
		self.DirDrive = self.Data[offset:offset+dirdriveref.Length]
		#print '%i %s' % (offset, self.DirDrive)
		offset += homedirref.Length + dirdriveref.PaddLen


		#outtest = self.AccountName
		#print '!!!! AN Length: %i  --%s--  %s' % (len(outtest), outtest, outtest.encode('hex'))

		#outtest = self.DisplayName #fullname
		#print '!!!! FN Length: %i  --%s--  %s' % (len(outtest), outtest, outtest.encode('hex'))

		#outtest = self.LogonScript
		#print '!!!! LS Length: %i  --%s--  %s' % (len(outtest), outtest, outtest.encode('hex'))

		#outtest = self.ProfilePath
		#print '!!!! PP Length: %i  --%s--  %s' % (len(outtest), outtest, outtest.encode('hex'))

		#outtest = self.HomeDir
		#print '!!!! HD Length: %i  --%s--  %s' % (len(outtest), outtest, outtest.encode('hex'))

		#outtest = self.DirDrive
		#print '!!!! DD Length: %i  --%s--  %s' % (len(outtest), outtest, outtest.encode('hex'))

		maxridcount = struct.unpack('<L', self.Data[offset:offset+4])[0]
		#print 'maxrid', maxridcount
		offset += 4
		grouprids = []
		for i in range(numrids):
			#print self.Data[offset:offset+12].encode('hex')
			grouprids.append(struct.unpack('<L', self.Data[offset:offset+4])[0])
			offset += 8

		self.Groups = grouprids

		# TODO: Decode and re-encode this
		self.extrajunk2 = self.Data[offset:]


	def encode(self):
		header = struct.pack('<BBH', self.Version, self.ByteOrder, self.HeaderLen) + \
			self.FillBytes 
		#	struct.pack('<QL', self.InitialLength,

		e = struct.pack('<L', 0x00020000) + \
			TimeToBytes(self.LogonTime) + \
			TimeToBytes(self.LogoffTime) + \
			TimeToBytes(self.KickoffTime) + \
			TimeToBytes(self.PwdLastSet) + \
			TimeToBytes(self.PwdCanChange) + \
			TimeToBytes(self.PwdMustChange) + \
			struct.pack('<HHL', len(self.AccountName), len(self.AccountName), 0x00020004) + \
			struct.pack('<HHL', len(self.DisplayName), len(self.DisplayName), 0x00020008) + \
			struct.pack('<HHL', len(self.LogonScript), len(self.LogonScript), 0x0002000c) + \
			struct.pack('<HHL', len(self.ProfilePath), len(self.ProfilePath), 0x00020010) + \
			struct.pack('<HHL', len(self.HomeDir),     len(self.HomeDir),     0x00020014) + \
			struct.pack('<HHL', len(self.DirDrive),    len(self.DirDrive),    0x00020018) + \
			struct.pack('<HHLLL', self.Logoncount, self.BadpPasswordCount, self.UserRid, self.GroupRid, len(self.Groups))
		
		# TODO: Decode and re-encode this
		e += self.extrajunk

		e +=struct.pack('<LLL', len(self.AccountName)/2, 0, len(self.AccountName)/2) + AlignedString(self.AccountName) + \
			struct.pack('<LLL', len(self.DisplayName)/2, 0, len(self.DisplayName)/2) + AlignedString(self.DisplayName) + \
			struct.pack('<LLL', len(self.LogonScript)/2, 0, len(self.LogonScript)/2) + AlignedString(self.LogonScript) + \
			struct.pack('<LLL', len(self.ProfilePath)/2, 0, len(self.ProfilePath)/2) + AlignedString(self.ProfilePath) + \
			struct.pack('<LLL', len(self.HomeDir)/2,     0, len(self.HomeDir)/2)     + AlignedString(self.HomeDir)     + \
			struct.pack('<LLL', len(self.DirDrive)/2,    0, len(self.DirDrive)/2)    + AlignedString(self.DirDrive)

		# Groups
		e += struct.pack('<L', len(self.Groups))
		for g in self.Groups:
			e += struct.pack('<LL', g, 7)

		# TODO: Decode and re-encode this
		e += self.extrajunk2

		header += struct.pack('<Q', len(e))

		#print 'LogInInfoLen %i' % len(e)

		#e += struct.pack('<LLL', len(self.AccountName), 0, len(self.AccountName)) #+ AlignedString(self.AccountName)

		return header + e

class PacClientInfo(PacInfoStructure):
	Type = 10
	PrettyName = 'Client Info'
	ClientID = None
	Name = None

	def __init__(self, pac, index=0):
		super(self.__class__, self).__init__(pac, index)
		if self.Type != 10:
			raise ValueError('PAC Information Structure is not Client Info')

		self.ClientID = BytesToTime(self.Data[:8])
		namelen = struct.unpack('<H', self.Data[8:10])[0]
		self.Name = self.Data[10:10+namelen].encode('utf-8')


	def __str__(self):
		return '%s (%i) ClientID: %s  Name (%i): %s' % (self.PrettyName, self.Type, str(self.ClientID), len(self.Name), self.Name)

	def encode(self):			
		return TimeToBytes(self.ClientID) + struct.pack('<H', len(self.Name)) + self.Name

class PacUpnDnsInfo(PacInfoStructure):
	Type = 12
	PrettyName = 'UPN DNS Info'
	UPNName = None
	DNSName = None
	Flags = None

	def __init__(self, pac, index=0):
		super(self.__class__, self).__init__(pac, index)
		if self.Type != 12:
			raise ValueError('PAC Information Structure is not UPN DNS Info')
		upnlen = struct.unpack('<H', self.Data[:2])[0]
		upnoffset = struct.unpack('<H', self.Data[2:4])[0]
		dnslen = struct.unpack('<H', self.Data[4:6])[0]
		dnsoffset = struct.unpack('<H', self.Data[6:8])[0]
		self.Flags = self.Data[8:12] # screw decoding this

		#print upnlen, upnoffset, dnslen, dnsoffset

		self.UPNName = self.Data[upnoffset:upnoffset+upnlen].decode('utf-8')
		self.DNSName = self.Data[dnsoffset:dnsoffset+dnslen].decode('utf-8')

	def __str__(self):
		return '%s (%i) Flags: %s  UPN Name: %s  DNS Name: %s' % (self.PrettyName, self.Type, '%0.8X' % struct.unpack('<L', self.Flags)[0], self.UPNName, self.DNSName)

	def encode(self):
		# seems to add lots of \x00\x00\x00\x00 at the end of strings
		return struct.pack('<HHHH', \
			# UPN Len \
			len(self.UPNName), \
			# UPN Offset \
			16, \
			# DNS Len \
			len(self.DNSName), \
			# DNS Offset \
			20+len(AlignedString(self.UPNName))) + \
			self.Flags + '\x00\x00\x00\x00' + str(AlignedString(self.UPNName)) + '\x00\x00\x00\x00' + str(AlignedString(self.DNSName))

class PacServerChecksum(PacInfoStructure):
	Type = 6
	PrettyName = 'Server Checksum'
	SigType = None
	SigVal = None

	def __init__(self, pac, index=0):
		super(self.__class__, self).__init__(pac, index)
		if self.Type != 6:
			raise ValueError('PAC Information Structure is not Server Checksum')
		self.SigType = struct.unpack('<l', self.Data[:4])[0]
		self.SigVal = self.Data[4:]

	def __str__(self):
		return '%s (%i) Size: %i  Sig Type: %i  SigVal: %s' % (self.PrettyName, self.Type, len(self.encode()), self.SigType, self.SigVal.encode('hex'))

	def encode(self):
		#return self.Data
		return struct.pack('<l', self.SigType) + self.SigVal

class PacKdcChecksum(PacInfoStructure):
	Type = 7
	PrettyName = 'Privsvr Checksum'
	SigType = None
	SigVal = None

	def __init__(self, pac, index=0):
		super(self.__class__, self).__init__(pac, index)
		if self.Type != 7:
			raise ValueError('PAC Information Structure is not KDC (Privsvr) Checksum')
		self.SigType = struct.unpack('<l', self.Data[:4])[0]
		self.SigVal = self.Data[4:]

	def __str__(self):
		return '%s (%i) Size: %i  Sig Type: %i  SigVal: %s' % (self.PrettyName, self.Type, len(self.encode()), self.SigType, self.SigVal.encode('hex'))

	def encode(self):
		#return self.Data
		return struct.pack('<l', self.SigType) + self.SigVal

class PacGenericInfo(PacInfoStructure):
	# Just in case there are other structures besides the original 5
	Type = None

	def __init__(self, pac, index=0):
		super(self.__class__, self).__init__(pac, index)

	def encode(self):
		#return self.Data
		super(self.__class__, self).__init__()


class PAC(object):
	_pac=None
	_loaded = False
	Version = 0

	PacLoginInfo = None
	PacClientInfo = None
	PacUpnDnsInfo = None
	PacServerChecksum = None
	PacKdcChecksum = None

	def __init__(self, pac=None):

		if pac == None:
			_pac = None
			_loaded = False
		else:
			self.load(pac)

	def __str__(self):
		retval  = str(self.PacLoginInfo)
		retval += str(self.PacClientInfo)
		retval += str(self.PacUpnDnsInfo)
		retval += str(self.PacServerChecksum)
		retval += str(self.PacKdcChecksum)
		return retval

	def load(self, pac):
		numentries, self.Version = struct.unpack('<II', pac[:8])

		#pacinfostructures = {}
		pacinfostructures = collections.defaultdict(lambda: PacGenericInfo)
		for cls in PacInfoStructure.__subclasses__():
			pacinfostructures[cls.Type] = cls


		for i in range(numentries):
			# 8 - num entries (4) and version (4)
			offset = 8 + 16 * i
			# get the type of the chunk
			typeval = struct.unpack('<L', pac[offset:offset+4])[0]
			# load the right class
			cls = pacinfostructures[typeval]
			pis = cls(pac, i)

			if pis.Type == 1:
				self.PacLoginInfo = pis
			elif pis.Type == 10:
				self.PacClientInfo = pis
			elif pis.Type == 12:
				self.PacUpnDnsInfo = pis
			elif pis.Type == 6:
				self.PacServerChecksum = pis
			elif pis.Type == 7:
				self.PacKdcChecksum = pis

			if pis.Data != pis.encode():
				print "NO MATCH!! %s" % pis.PrettyName

				cmp(pis.Data, pis.encode(), verbose=True)
				#print '%s\n%s' % (pis.Data.encode('hex'), pis.encode().encode('hex'))
				print '----'


	def encode(self):
		e = struct.pack('<LL', 5, self.Version)

		# the inital offset value is always 88
		# ok, so I lied. it is actually the sum of a bunch of crap that doesn't seem to change
		offset = 88
		alignedoffset = 88

		headers = ''
		payload = ''

		pacstructs = [self.PacLoginInfo, self.PacClientInfo, self.PacUpnDnsInfo, self.PacServerChecksum, self.PacKdcChecksum]

		for ps in pacstructs:
			pse = ps.encode()
			psealigned = AlignedString(pse, 8)

			headers += struct.pack('<IIII', ps.Type, len(pse), offset, 0)
			payload += psealigned

			#print '%16s Offset: %3s  Aligned Offset: %3s  Length: %3s  Aligned Length: %3s' % (ps.PrettyName, offset, alignedoffset, len(psed), len(AlignedString(psed, 8)))

			offset += len(psealigned)

		return e + headers + payload



def cmp(s1, s2, comparelen=None, verbose=False):
	if not comparelen:
		if len(s1) <= len(s2):
			comparelen = len(s1)
		else:
			comparelen = len(s2)

	if s1[:comparelen] == s2[:comparelen]:
		if verbose:
			print 'SAME %i %i' % (len(s1), len(s2))
		return True
	else:
		if verbose:
			print 'NOT SAME'
			print s1[:comparelen].encode('hex')
			print
			print s2[:comparelen].encode('hex')
		return False



def main():
	#a ='050000000000000001000000b001000058000000000000000a0000000e00000008020000000000000c000000480000001802000000000000060000001400000060020000000000000700000014000000780200000000000001100800cccccccca001000000000000000002005ee808c4fecdcf01ffffffffffffff7fffffffffffffff7f1ac0dc109ec6cf011a80463b67c7cf01ffffffffffffff7f04000400040002000400040008000200000000000c000200000000001000020000000000140002000000000018000200b30000005204000000020000010000001c000200200000000000000000000000000000000000000008000a00200002000a000c00240002002800020000000000000000001002000000000000000000000000000000000000000000000000000000000000010000002c00020000000000000000000000000002000000000000000200000074006d0002000000000000000200000074006d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000200000700000005000000000000000400000044004300300031000600000000000000050000004d004500440049004e00000004000000010400000000000515000000bffab31eb43b681af8cdadb10100000030000200070000000100000001010000000000120100000000000000800eafcefecdcf01040074006d0000001c00100016003000010000000000000074006d0040006d006500640069006e002e006c006f00630061006c00000000004d004500440049004e002e004c004f00430041004c00000076ffffffce1884addcbeade3e2eb24d9920a294f0000000076ffffff6cb8692b47afb295b541b4fe9a0a058c00000000'

	# xp-success
	#a = '050000000000000001000000a801000058000000000000000a0000000e00000000020000000000000c000000480000001002000000000000060000001400000058020000000000000700000014000000700200000000000001100800cccccccc9801000000000000000002006cd0e2cf07afce01ffffffffffffff7fffffffffffffff7f6595bf65d875ce0165552990a176ce01ffffffffffffff7f04000400040002000000000008000200000000000c000200000000001000020000000000140002000000000018000200460000005204000001020000010000001c000200200000000000000000000000000000000000000008000a00200002000a000c00240002002800020000000000000000001002000000000000000000000000000000000000000000000000000000000000010000002c00020000000000000000000000000002000000000000000200000074006d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000010200000700000005000000000000000400000044004300300031000600000000000000050000004d004500440049004e00000004000000010400000000000515000000bffab31eb43b681af8cdadb10100000030000200070000000100000001010000000000120100000080dc05d007afce01040074006d0000001c00100016003000010000000000000074006d0040006d006500640069006e002e006c006f00630061006c00000000004d004500440049004e002e004c004f00430041004c00000076ffffffd0293d55a40ae227b4826d87f5f3806b0000000076ffffffb7b53a4ac414e436a7e58845f5e419c000000000'

	# 7-success
	#a = '050000000000000001000000b001000058000000000000000a0000000e00000008020000000000000c000000480000001802000000000000060000001400000060020000000000000700000014000000780200000000000001100800cccccccca00100000000000000000200c605fb3210d5cf01ffffffffffffff7fffffffffffffff7f1ac0dc109ec6cf011a80463b67c7cf01ffffffffffffff7f04000400040002000400040008000200000000000c000200000000001000020000000000140002000000000018000200c20000005204000001020000010000001c000200200000000000000000000000000000000000000008000a00200002000a000c00240002002800020000000000000000001002000000000000000000000000000000000000000000000000000000000000010000002c00020000000000000000000000000002000000000000000200000074006d0002000000000000000200000074006d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000010200000700000005000000000000000400000044004300300031000600000000000000050000004d004500440049004e00000004000000010400000000000515000000bffab31eb43b681af8cdadb1010000003000020007000000010000000101000000000012010000000000000080353e9110d5cf01040074006d0000001c00100016003000010000000000000074006d0040006d006500640069006e002e006c006f00630061006c00000000004d004500440049004e002e004c004f00430041004c00000076ffffff7383d9c6b5854086d8997b5ac7a632260000000076ffffff20bfc7689277658ad2c21fdc475d6c2300000000'

	# 7-success-administrator
	#a = '0500000000000000010000003002000058000000000000000a0000002400000088020000000000000c00000060000000b002000000000000060000001400000010030000000000000700000014000000280300000000000001100800cccccccc2002000000000000000002008d5c003e13d5cf01ffffffffffffff7fffffffffffffff7f0f29e0c9d775ce010fe949f4a076ce01ffffffffffffff7f1a001a00040002001a001a0008000200000000000c00020000000000100002000000000014000200000000001800020078000000f401000001020000060000001c000200200200000000000000000000000000000000000008000a00200002000a000c00240002002800020000000000000000001002000000000000000000000000000000000000000000000000000000000000010000002c0002003400020001000000380002000d000000000000000d000000410064006d0069006e006900730074007200610074006f00720000000d000000000000000d000000410064006d0069006e006900730074007200610074006f00720000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000008020000070000000102000007000000000200000700000007020000070000000602000007000000650400000700000005000000000000000400000044004300300031000600000000000000050000004d004500440049004e00000004000000010400000000000515000000bffab31eb43b681af8cdadb10100000030000200070000000100000001010000000000120100000004000000010400000000000515000000bffab31eb43b681af8cdadb1010000003c0200000700002000000000808bb97613d5cf011a00410064006d0069006e006900730074007200610074006f0072000000000032001000160048000000000000000000410064006d0069006e006900730074007200610074006f00720040006d006500640069006e002e006c006f00630061006c000000000000004d004500440049004e002e004c004f00430041004c00000076ffffff84faca5fb556ef458c3200e64a3b96ca0000000076ffffff051fc3c03c92775ab3a24d24dc11a19700000000'

	# ram
	a = '050000000000000001000000b001000058000000000000000a0000000e00000008020000000000000c000000480000001802000000000000060000001400000060020000000000000700000014000000780200000000000001100800cccccccca001000000000000000002005ee808c4fecdcf01ffffffffffffff7fffffffffffffff7f1ac0dc109ec6cf011a80463b67c7cf01ffffffffffffff7f04000400040002000400040008000200000000000c000200000000001000020000000000140002000000000018000200b30000005204000001020000010000001c000200200000000000000000000000000000000000000008000a00200002000a000c00240002002800020000000000000000001002000000000000000000000000000000000000000000000000000000000000010000002c00020000000000000000000000000002000000000000000200000074006d0002000000000000000200000074006d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000010200000700000005000000000000000400000044004300300031000600000000000000050000004d004500440049004e00000004000000010400000000000515000000bffab31eb43b681af8cdadb10100000030000200070000000100000001010000000000120100000000000000800eafcefecdcf01040074006d0000001c00100016003000010000000000000074006d0040006d006500640069006e002e006c006f00630061006c00000000004d004500440049004e002e004c004f00430041004c00000076ffffffce1884addcbeade3e2eb24d9920a294f0000000076ffffff6cb8692b47afb295b541b4fe9a0a058c00000000'

	a = a.decode('hex')

	p = PAC(a)
	print p.PacLoginInfo.GroupRid
	p.PacLoginInfo.GroupRid = 77
	print p.PacLoginInfo.GroupRid
	#print p


	p2 = p.encode()

	#cmp(a, p2, None, True)

	print a == p2





if __name__ == '__main__':
	main()


