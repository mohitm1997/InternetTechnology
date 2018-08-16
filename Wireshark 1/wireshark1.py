#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import dpkt
import socket
import argparse
#import win_inet_pton
from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code 
def main():
    number_of_packets = 0             # you can use these structures if you wish 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing 
    input_data=dpkt.pcap.Reader(open(filename,'rb'))

    # this main loop reads the packets one at a time from the pcap file
    for timestamp, packet in input_data:
    	number_of_packets += 1
        eth = dpkt.ethernet.Ethernet(packet)

        
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        	continue

        ip = eth.data
        ipaddr = inet_to_str(ip.src)
        
        if ipaddr in list_of_ips:
        	list_of_ips[ipaddr]	+= 1
        else:
        	list_of_ips[ipaddr] = 1

        if ip.p == dpkt.ip.IP_PROTO_TCP:
        	tcp = ip.data
        	dport = tcp.dport
        	if dport in list_of_tcp_ports:
        		list_of_tcp_ports[dport] += 1
        	else:
        		list_of_tcp_ports[dport] = 1

        	ip_dport = ipaddr + ":" + str(dport)
        	if ip_dport	in list_of_ip_tcp_ports:
        		list_of_ip_tcp_ports[ip_dport] += 1
        	else:
        		list_of_ip_tcp_ports[ip_dport] = 1

    ips_sorted = OrderedDict(sorted(list_of_ips.items(), key=lambda x: x[1], reverse=True))
    tcp_sorted = OrderedDict(sorted(list_of_tcp_ports.items(), key=lambda x: x[1], reverse=True))
    ip_port_sorted = OrderedDict(sorted(list_of_ip_tcp_ports.items(), key=lambda x: x[1], reverse=True))

    print "CS 352 Wireshark, part 1"
    print "Total number of packets, " + str(number_of_packets)

    print "Source IP Addresses, count"
    for ip in ips_sorted:
    	print ip + "," + str(ips_sorted[ip])

    print "Destination TCP ports, count"
    
    for dport in tcp_sorted:
    	print str(dport) + "," + str(tcp_sorted[dport])

    print "Source IPs/Destination TCP ports, count"	

    for ip_dport in ip_port_sorted:
    	print ip_dport + "," + str(ip_port_sorted[ip_dport])    

# execute a main function in Python
if __name__ == "__main__":
    main()    
