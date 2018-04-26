#!/usr/bin/python

import socket
import os
import struct
import binascii

def analyze_ether_header(data):
	ip_bool = False
	#Unpack destination address, source address, and ethertype in the packet
	eth_hdr = struct.unpack("!6s6sH", data[:14])
	
	dest_mac = binascii.hexlify(eth_hdr[0]) #Destination MAC address
	src_mac  = binascii.hexlify(eth_hdr[1]) #Source MAC address.
	proto    = eth_hdr[2] #Next protocol.
	
	print "<======================ETHERNET HEADER======================>"
	print "Destination MAC Address\t: " + dest_mac[:2] + ":" + dest_mac[2:4] + ":" +  dest_mac[4:6] + ":" + dest_mac[6:8] + ":" + dest_mac[8:10] + ":" + dest_mac[10:]
	print "Source MAC Address\t: " + src_mac[:2] + ":" + src_mac[2:4] + ":" +  src_mac[4:6] + ":" + src_mac[6:8] + ":" + src_mac[8:10] + ":" + src_mac[10:]
	print "Protocol\t\t:\t%s" % hex(proto)
	
	if hex(proto) == "0x800": #IPV4
		ip_bool = True
		
	data = data[14:]
	return data, ip_bool
	
def analyze_ip_header(data):
	ip_hdr = struct.unpack("!6H4s4s", data[:20])
	version = ip_hdr[0] >> 12 # Version
	ihl     = (ip_hdr[0] >> 8) & 0x0f #IHL #0f = 00001111
	tos     = (ip_hdr[0]) & 0x00ff	#Type of Service
	tot_len = ip_hdr[1] #Total Length
	ip_id   = ip_hdr[2] #Identification
	flags   = ip_hdr[3] >> 13 #Flags
	frag_offset = ip_hdr[3] & 0x1fff #Fragment Offset
	ttl         = (ip_hdr[4] >> 8) #Time to Live
	ip_proto    = ip_hdr[4] & 0x00ff #Protocol
	hdr_chksum  = ip_hdr[5] #Header Checksum
	#ntoa : Network To ASCII
	src_addr    = socket.inet_ntoa(ip_hdr[6]) #Source IP address
	dest_addr   = socket.inet_ntoa(ip_hdr[7]) #Destination IP address
	
	if ip_proto == 6: #TCP Magic Number
		next_proto = "TCP"
	elif ip_proto == 17: #UDP Magic Number
		next_proto = "UDP"
	else:
		return	
	
	print "<======================IP HEADER======================>"
	print "Version\t\t:\t%s" %version # Version
	print "IHL\t\t:\t%s" %ihl #IHL #0f = 00001111
	print "TOS\t\t:\t%s" %tos #Type of Service
	print "Total Length\t:\t%s" % tot_len #Total Length
	print "Identification\t:\t%s" %ip_id #Identification
	print "Flags\t\t:\t%s" %flags #Flags
	print "Fragmentation Offset:\t%s" %frag_offset #Fragment Offset
	print "TTL\t\t:\t%s" %ttl #Time to Live
	print "Next Protocol\t:\t%s" %ip_proto #Protocol
	print "Header Checksum\t:\t%s" %hdr_chksum #Header Checksum
	#ntoa : Network To ASCII
	print "Source IP\t:\t%s" %src_addr#Source IP address
	print "Destination Address:\t%s" %dest_addr
	data = data[20:]
	return data, next_proto
	
def analyze_tcp_header(data):
	tcp_hdr = struct.unpack("!2H2I4H", data[:20])
	src_port = tcp_hdr[0] #Source Port
	dst_port = tcp_hdr[1] #Destination Port
	seq_nbr  = tcp_hdr[2] #Sequence Number
	ack_nbr  = tcp_hdr[3] #Acknowledgement Number
	data_offset = tcp_hdr[4] >> 12 #Data Offset
	reserved    = (tcp_hdr[4] >> 6) & 0x003f #Reserved
	urg_flg     = (tcp_hdr[4] >> 5) & 0x0001 #Urgent Flag
	ack_flg     = (tcp_hdr[4] >> 4) & 0x0001 #Acknowledgement Flag
	psh_flg     = (tcp_hdr[4] >> 3) & 0x0001 #Push Flag
	rst_flg     = (tcp_hdr[4] >> 2) & 0x0001 #Reset Flag
	syn_flg     = (tcp_hdr[4] >> 1) & 0x0001 # Synchronize Flag
	fin_flg     = (tcp_hdr[4]) & 0x0001 # FInish Flag
	window      = tcp_hdr[5] #Window
	chksum      = tcp_hdr[6] #Checksum
	urg_ptr     = tcp_hdr[7] #Urgent Pointer
	
	print "<======================TCP HEADER======================>"
	print "Source Port\t\t:\t%s" %src_port #Source Port
	print "Destination Port\t\t:\t%s" %dst_port #Destination Port
	print "Sequence Number\t\t:\t%s" %seq_nbr#Sequence Number
	print "Acknowledgement Number\t:\t%s" %ack_nbr  #Acknowledgement Number
	print "Data Offset\t\t:\t%s" %data_offset#Data Offset
	print "Reserved\t\t:\t%s" %reserved #Reserved
	print "Urgent Flag\t\t:\t%s" %urg_flg #Urgent Flag
	print "Acknowledgement Flag\t\t:\t%s" %ack_flg #Acknowledgement Flag
	print "Push Flag\t\t:\t%s" %psh_flg #Push Flag
	print "Reset Flag\t\t:\t%s" %rst_flg #Reset Flag
	print "Synchronization Flag\t\t:\t%s" %syn_flg # Synchronize Flag
	print "Finish Flag\t\t:\t%s" %fin_flg # FInish Flag
	print "Window\t\t:\t%s" %window #Window
	print "Checksum\t\t:\t%s" %chksum #Checksum
	print "Urgent Pointer\t\t:\t%s" %urg_ptr
	
	data = data[20:]
	return data

def analyze_udp_header(data):
	udp_header = struct.unpack("!4H", data[:8])
	src_prt = udp_header[0]
	dst_prt = udp_header[1]
	length  = udp_header[2]
	chksum  = udp_header[3]
	
	print "<======================UDP HEADER======================>"
	print "Source Port\t:\t%s" %src_prt
	print "Destination Port:\t%s" %dst_prt
	print "Length\t\t:\t%s" %length
	print "Checksum\t:\t%s" %chksum
	
	data = data[4:]
	return data

def main():
	
	sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  #PF_PACKET asks the OS to give an untampered packet. htons 0x0003 means we need to get all types of packets
#	sniffer_socket.bind(()) <==== DON'T DO THIS. Since we will need all the packets, we will be listening to all the ports on the machine.
	recv_data = sniffer_socket.recv(2048)
	os.system("clear")
	data, ip_bool = analyze_ether_header(recv_data)
	if ip_bool == True:
		data, next_proto = analyze_ip_header(data)
	else:
		return 
		
	if next_proto == "TCP":
		analyze_tcp_header(data)
	elif next_proto == "UDP":
		analyze_udp_header(data)
	

while True:
	main()
