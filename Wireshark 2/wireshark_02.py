#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse
#import win_inet_pton
import copy


# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.

def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'rb'))

    list_of_tcp_time = list()
    list_of_tcp_port = list()
    list_of_udp_time = list()
    list_of_udp_port = list()

    for timestamp, packet in input_data:

        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        	continue

        ip = eth.data
        destip = inet_to_str(ip.dst)

        if destip != target_ip:
        	continue

        time_string = datetime.datetime.utcfromtimestamp(timestamp)

        if ip.p == dpkt.ip.IP_PROTO_TCP:
        	list_of_tcp_time.append([time_string, ip, 0])
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
        	list_of_udp_time.append([time_string, ip, 0])

    list_of_tcp_port = sorted(list_of_tcp_time, key=lambda x: x[1].data.dport)
    list_of_udp_port = sorted(list_of_udp_time, key=lambda x: x[1].data.dport)

    probes_list_tcp = list()
    i = 0
    while i < len(list_of_tcp_time):

    	if list_of_tcp_time[i][2] == 1:
    		i += 1
    		continue

    	buffer = list()
    	if i+1 < len(list_of_tcp_time):
    		j = i + 1
    		x = i
    		while list_of_tcp_time[j][0] < list_of_tcp_time[x][0] + datetime.timedelta(seconds = W_p):
    			if len(buffer) == 0:
    				buffer.append(list_of_tcp_time[x])
    				list_of_tcp_time[x][2] = 1

    			if list_of_tcp_time[j][1].data.dport == list_of_tcp_time[x][1].data.dport:
    				buffer.append(list_of_tcp_time[j])
    				list_of_tcp_time[j][2] = 1
    				x=j
    			j += 1
    			if j >= len(list_of_tcp_time):
    				break

    	if len(buffer) >= N_p:
    		probes_list_tcp.append(copy.deepcopy(buffer))

    	i += 1

    probes_list_udp = list()
    i = 0
    while i < len(list_of_udp_time):

    	if list_of_udp_time[i][2] == 1:
    		i += 1
    		continue

    	buffer = list()
    	if i+1 < len(list_of_udp_time):
    		j = i + 1
    		x = i
    		while list_of_udp_time[j][0] < list_of_udp_time[x][0] + datetime.timedelta(seconds = W_p):
    			if len(buffer) == 0:
    				buffer.append(list_of_udp_time[x])
    				list_of_udp_time[x][2] = 1

    			if list_of_udp_time[j][1].data.dport == list_of_udp_time[x][1].data.dport:
    				buffer.append(list_of_udp_time[j])
    				list_of_udp_time[j][2] = 1
    				x = j
    			j += 1
    			if j >= len(list_of_udp_time):
    				break

    	if len(buffer) >= N_p:
    		probes_list_udp.append(copy.deepcopy(buffer))

    	i += 1

    scans_list_tcp = list()
    i = 0
    while i < len(list_of_tcp_port):
    	buffer = list()
    	if i+1 < len(list_of_tcp_port):
    		j = i + 1
    		while list_of_tcp_port[j][1].data.dport < list_of_tcp_port[i][1].data.dport + W_s:
    			if len(buffer) == 0:
    				buffer.append(list_of_tcp_port[i])
    			buffer.append(list_of_tcp_port[j])
    			i = j
    			j += 1
    			if j >= len(list_of_tcp_port):
    				break

    	if len(buffer) >= N_s:
    		scans_list_tcp.append(copy.deepcopy(buffer))
    		i=j-1

    	i += 1

    scans_list_udp = list()
    i = 0
    while i < len(list_of_udp_port):
    	buffer = list()
    	if i+1 < len(list_of_udp_port):
    		j = i + 1
    		while list_of_udp_port[j][1].data.dport < list_of_udp_port[i][1].data.dport + W_s:
    			if len(buffer) == 0:
    				buffer.append(list_of_udp_port[i])
    			buffer.append(list_of_udp_port[j])
    			i = j
    			j += 1
    			if j >= len(list_of_udp_port):
    				break

    	if len(buffer) >= N_s:
    		scans_list_udp.append(copy.deepcopy(buffer))
    		i=j-1

    	i += 1

    print "CS 352 Wireshark (Part 2)\nReports for TCP"
    print "Found " + str(len(probes_list_tcp)) + " probes"
    if len(probes_list_tcp) != 0:
    	for probe in probes_list_tcp:
    		print "Probe: [" + str(len(probe)) + " Packets]"
    		for packet in probe:
    			print "\tPacket [Timestamp: " + str(packet[0]) + ", Port: " + str(packet[1].data.dport) + ", Source IP: " + inet_to_str(packet[1].src) + "]"
    print "Found " + str(len(scans_list_tcp)) + " scans"
    if len(scans_list_tcp) != 0:
    	for scan in scans_list_tcp:
    		print "Scan: [" + str(len(scan)) + " Packets]"
    		for packet in scan:
    			print "\tPacket [Timestamp: " + str(packet[0]) + ", Port: " + str(packet[1].data.dport) + ", Source IP: " + inet_to_str(packet[1].src) + "]"
    print "Reports for UDP"
    print "Found " + str(len(probes_list_udp)) + " probes"
    if len(probes_list_udp) != 0:
    	for probe in probes_list_udp:
    		print "Probe: [" + str(len(probe)) + " Packets]"
    		for packet in probe:
    			print "\tPacket [Timestamp: " + str(packet[0]) + ", Port: " + str(packet[1].data.dport) + ", Source IP: " + inet_to_str(packet[1].src) + "]"
    print "Found " + str(len(scans_list_udp)) + " scans"
    if len(scans_list_udp) != 0:
    	for scan in scans_list_udp:
    		print "Scan: [" + str(len(scan)) + " Packets]"
    		for packet in scan:
    			print "\tPacket [Timestamp: " + str(packet[0]) + ", Port: " + str(packet[1].data.dport) + ", Source IP: " + inet_to_str(packet[1].src) + "]"


# execute a main function in Python
if __name__ == "__main__":
    main()
