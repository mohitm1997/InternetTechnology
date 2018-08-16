# sock352.py 

# (C) 2018 by R. P. Martin, under the GPL license, version 2.

# this is the skeleton code that defines the methods for the sock352 socket library, 
# which implements a reliable, ordered packet stream using go-back-N.
#
# Note that simultaneous close() is required, does not support half-open connections ---
# that is outstanding data if one side closes a connection and continues to send data,
# or if one side does not close a connection the protocol will fail. 

import socket as ip
import random
import binascii
import threading
import time
import sys
import struct as st
import os
import signal

# The first byte of every packet must have this value 
MESSAGE_TYPE = 0x44

# this defines the sock352 packet format.
# ! = big endian, b = byte, L = long, H = half word
HEADER_FMT = '!bbLLH'

# this are the flags for the packet header 
SYN =  0x01    # synchronize 
ACK =  0x02    # ACK is valid 
DATA = 0x04    # Data is valid 
FIN =  0x08    # FIN = remote side called close 

# max size of the data payload is 63 KB
MAX_SIZE = (63*1024)

# max size of the packet with the headers 
MAX_PKT = ((16+16+16)+(MAX_SIZE))

# these are the socket states 
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN  = 3
STATE_SYNRECV = 4 
STATE_ESTABLISHED = 5
STATE_CLOSING =  6
STATE_CLOSED =   7
STATE_REMOTE_CLOSED = 8


# function to print. Higher debug levels are more detail
# highly recommended 
def dbg_print(level,string):
	global sock352_dbg_level 
	if (sock352_dbg_level >=  level):
		print string 
		return 

# this is the thread object that re-transmits the packets 
class sock352Thread (threading.Thread):

	def __init__(self, threadID, name, delay):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.delay = float(delay)
		
	def run(self):
		dbg_print(3,("sock352: timeout thread starting %s delay %.3f " % (self.name,self.delay)) )
		scan_for_timeouts(self.delay)
		dbg_print(3,("sock352: timeout thread %s Exiting " % (self.name)))
		return 

# Example timeout thread function
# every <delay> seconds it wakes up and re-transmits packets that
# have been sent, but not received. A received packet with a matching ack
# is removed from the list of outstanding packets.

def scan_for_timeouts(delay):
	global list_of_outstanding_packets
	list_of_outstanding_packets = list()
	time.sleep(delay)

	# there is a global socket list, although only 1 socket is supported for now 
	while ( True ):

		time.sleep(delay)
		if len(list_of_outstanding_packets) == 0:
			continue
		for packet in list_of_outstanding_packets: 
			current_time = time.time()
			time_diff = float(current_time) - float(packet.timeStamp)

			if (time_diff > delay):
				dbg_print(3,"sock352: packet timeout, retransmitting")
				#print "TIMEOUT -- RETRANSMITTING"
				toSend = packet.packet.pack()
				packet.sock.sock.sendto(toSend, packet.sock.destAddr)
	return 


# This class holds the data of a packet gets sent over the channel 
# 
class Packet:
	def __init__(self):
		self.type = MESSAGE_TYPE    # ID of sock352 packet
		self.cntl = 0               # control bits/flags 
		self.seq = 0                # sequence number 
		self.ack = 0                # acknowledgement number 
		self.size = 0               # size of the data payload 
		self.data = b''             # data 

	# unpack a binary byte array into the Python fields of the packet 
	def unpack(self,bytes):
		# check that the data length is at least the size of a packet header 
		data_len = (len(bytes) - st.calcsize('!bbLLH'))
		if (data_len >= 0): 
			new_format = HEADER_FMT + str(data_len) + 's'
			values = st.unpack(new_format,bytes)
			self.type = values[0]
			self.cntl = values[1]
			self.seq  = values[2]
			self.ack  = values[3]
			self.size = values[4] 
			self.data = values[5]
			# you dont have to have to implement the the dbg_print function, but its highly recommended 
			dbg_print (1,("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data))))
		else:
			dbg_print (2,("sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

		return

	# returns a byte array from the Python fields in a packet 
	def pack(self):
		if (self.data == None): 
			data_len = 0
		else:
			data_len = len(self.data)
			if (data_len == 0):
				bytes = st.pack('!bbLLH',self.type,self.cntl,self.seq,self.ack,self.size)
			else:
				new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s' 
				dbg_print(5,("cs352 pack: %d %d %d %d %d %s " % (self.type,self.cntl,self.seq,self.ack,self.size,self.data)))
				bytes = st.pack(new_format,self.type,self.cntl,self.seq,self.ack,self.size,self.data)
			return bytes

	# this converts the fields in the packet into hexadecimal numbers 
	def toHexFields(self):
		if (self.data == None):
			retstr=  ("type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
		else:
			retstr= ("type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
			return retstr

	# this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
	def toHex(self):
		if (self.data == None):
			retstr=  ("%x%x%x%xx%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
		else:
			retstr= ("%x%x%x%x%xx%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
			return retstr




class packetMetaContainer():

	def __init__(self, packet, socket):
		self.timeStamp = 0
		self.packet = packet
		self.sock = socket

# the main socket class
# you must fill in all the methods
# it must work against the class client and servers
# with various drop rates

class Socket:

	def __init__(self):
		self.sock = ip.socket(ip.AF_INET,ip.SOCK_DGRAM)
		self.sockState = STATE_INIT
		self.destAddr = None
		self.currsequence = 0
		self.list_of_out_of_order_packets = list()
		self.lastSequenceReceived = 0
		self.remoteClosed = 0
		self.windowSize = 3
		self.drop = 0
		self.synAckSeq = 0
		return 

	# Print a debugging statement line
	# 
	# 0 == no debugging, greater numbers are more detail.
	# You do not need to implement the body of this method,
	# but it must be in the library.
	def set_debug_level(self, level):
		pass 

	# Set the % likelihood to drop a packet
	#
	# you do not need to implement the body of this method,
	# but it must be in the library,
	def set_drop_prob(self, probability):
		if probability >= 0.0 and probability <= 1.0:
			self.drop = probability
		else:
			self.drop = 0.0
			#print "INVALID PROB"
	# Set the seed for the random number generator to get
	# a consistent set of random numbers
	# 
	# You do not need to implement the body of this method,
	# but it must be in the library.
	def set_random_seed(self, seed):
		self.random_seed = seed 
		

	# bind the address to a port
	# You must implement this method
	#
	def bind(self,address):
		self.sock.bind(address)
		return

	# connect to a remote port
	# You must implement this method
	def connect(self,address):
		#print "IN CONNECT"
		synPacket = Packet()
		synPacket.cntl = SYN
		synPacket.seq = random.randint(0,65535)
		self.currsequence = synPacket.seq
		toSend = synPacket.pack()
		self.destAddr = address
		#print "SENDING SYN"
		self.sock.sendto(toSend,address)
		self.state = STATE_SYNSENT
		data, sourceAddr = self.sock.recvfrom(MAX_PKT)
		receivedSYNACKPack = Packet()
		receivedSYNACKPack.unpack(data)
		while receivedSYNACKPack.cntl != SYN | ACK and receivedSYNACKPack.ack != self.currsequence:
			data, sourceAddr = self.sock.recvfrom(MAX_PKT)
			receivedSYNACKPack = Packet()
			receivedSYNACKPack.unpack(data)
		#print "RECEIVED SYN ACK"
		self.sockState = STATE_ESTABLISHED
		ackPacket = Packet()
		ackPacket.cntl = ACK
		ackPacket.ack = receivedSYNACKPack.seq
		self.lastSequenceReceived = receivedSYNACKPack.seq
		toSend = ackPacket.pack()
		self.sock.sendto(toSend,address)
		#print "CLIENT CONN ESTABLISHED"


	#accept a connection
	def accept(self):
		#print "IN ACCEPT"
		self.sockState = STATE_LISTEN
		data, sourceAddr = self.sock.recvfrom(MAX_PKT)
		self.destAddr = sourceAddr
		receivedSYNPack = Packet()
		receivedSYNPack.unpack(data)
		while receivedSYNPack.cntl != SYN:
			#print "NOT SYN PACKET"
			data, sourceAddr = self.sock.recvfrom(MAX_PKT)
			receivedSYNPack = Packet()
			receivedSYNPack.unpack(data)
		self.sockState = STATE_SYNRECV
		synAckPacket = Packet()
		synAckPacket.cntl = SYN | ACK
		self.currsequence = random.randint(0,65535)
		synAckPacket.seq = self.currsequence 
		self.synAckSeq = synAckPacket.seq
		synAckPacket.ack = receivedSYNPack.seq
		self.lastSequenceReceived = receivedSYNPack.seq
		toSend = synAckPacket.pack()
		#print "SEDNING SYNACK"
		self.sock.sendto(toSend, sourceAddr)

		return sourceAddr


	# send a message up to MAX_DATA
	# You must implement this method     
	def sendto(self,buffer):
		#print "IN SENDTO"
		if len(buffer) > MAX_SIZE:
			print "DATA TOO BIG"
			return
		if buffer == None:
			buffer = ""
		sendPacket = Packet()
		sendPacket.cntl = DATA
		self.currsequence += 1
		sendPacket.seq = self.currsequence
		sendPacket.size = len(buffer)
		sendPacket.data = buffer
		containedPacket = packetMetaContainer(sendPacket, self)
		list_of_outstanding_packets.append(containedPacket)
		toSend = sendPacket.pack()
		bytesSent = self.sock.sendto(toSend,self.destAddr)
		#print "SENT"
		containedPacket.timeStamp = time.time()
		return bytesSent


	# receive a message up to MAX_DATA
	# You must implement this method     
	def recvfrom(self,nbytes):
		#print "INSIDE RECVFROM"
		while self.sockState == STATE_SYNRECV:
			data, sourceAddr = self.sock.recvfrom(MAX_PKT)
			receivedPack = Packet()
			receivedPack.unpack(data)
			if receivedPack.cntl == ACK:
				if receivedPack.ack == self.synAckSeq:
					#print "SERVER CONN ESTABLISHED"
					self.sockState = STATE_ESTABLISHED
				else:
					#print "ACK DID NOT MATCH SEQ OF SYNACK"
					continue
			else:
				#print "RECEIVED PACK WAS NOT ACK PACKET"
				continue
		while self.sockState == STATE_ESTABLISHED:
			if len(self.list_of_out_of_order_packets) > 0 and self.list_of_out_of_order_packets[0].seq == self.lastSequenceReceived + 1:
				receivedPack = self.list_of_out_of_order_packets[0]
				data = self.list_of_out_of_order_packets[0].data
				del self.list_of_out_of_order_packets[0]
				self.lastSequenceReceived += 1
				return data
			else:
				data, sourceAddr = self.sock.recvfrom(MAX_PKT)
				receivedPack = Packet()
				receivedPack.unpack(data)
			if receivedPack.cntl & DATA == DATA:
				if receivedPack.seq == self.lastSequenceReceived + 1:
					#print "RECEIVED IN ORDER PACKET"
					drop = random.random()
					if drop <= self.drop:
						#print "DROPPED"
						continue
					ackPacket = Packet()
					ackPacket.cntl = ACK
					ackPacket.ack = receivedPack.seq
					toSend = ackPacket.pack()
					#print "SENDING ACK"
					self.sock.sendto(toSend,self.destAddr)
					self.lastSequenceReceived += 1
					return receivedPack.data
				if receivedPack.seq > self.lastSequenceReceived + 1:
					#print "RECEIVED OUT OF ORDER PACKET"
					duplicate = 0
					for pack in self.list_of_out_of_order_packets:
						if pack.seq == receivedPack.seq:
							duplicate = 1
					
					if duplicate == 0:
						self.list_of_out_of_order_packets.append(receivedPack)
						ackPacket = Packet()
						ackPacket.cntl = ACK
						ackPacket.ack = receivedPack.seq
						toSend = ackPacket.pack()
						#print "SENDING ACK"
						self.sock.sendto(toSend,self.destAddr)
					else:
						#print "DUPLICATE"
						continue
			if receivedPack.cntl & ACK == ACK:
				#print "RECEIVED ACK"
				for outstanding in list_of_outstanding_packets:
					if outstanding.packet.seq == receivedPack.ack:
						#print "REMOVING FROM OUTSTANDING2"
						list_of_outstanding_packets.remove(outstanding)
						break
			if receivedPack.cntl == FIN:
				self.remoteClosed = 1

	# close the socket and make sure all outstanding
	# data is delivered 
	# You must implement this method         
	def close(self):
		#print "INSIDE CLOSE"
		finPacket = Packet()
		finPacket.cntl = FIN
		self.currsequence += 1
		finPacket.seq = self.currsequence
		toSend = finPacket.pack()
		self.sock.sendto(toSend,self.destAddr)
		#print "FIN SENT"
		self.sockState = STATE_CLOSING
		while len(list_of_outstanding_packets) > 0 or self.remoteClosed == 0:
			data, sourceAddr = self.sock.recvfrom(MAX_PKT)
			receivedPack = Packet()
			receivedPack.unpack(data)

			if receivedPack.cntl == FIN:
				#print "REMOTE CLOSED"
				self.remoteClosed = 1

			elif receivedPack.cntl == ACK:
				for outstanding in list_of_outstanding_packets:
					if outstanding.packet.seq == receivedPack.ack:
						#print "REMOVING FROM OUTSTANDING"
						list_of_outstanding_packets.remove(outstanding)
						break
			time.sleep(.25)

		return
		
# Example how to start a start the timeout thread
global sock352_dbg_level 
sock352_dbg_level = 0
dbg_print(3,"starting timeout thread")

# create the thread 
thread1 = sock352Thread(1, "Thread-1", 0.25)

# you must make it a daemon thread so that the thread will
# exit when the main thread does. 
thread1.daemon = True

# run the thread 
thread1.start()


