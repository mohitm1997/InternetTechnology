#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse
#import win_inet_pton


# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.


def main():
    number_of_packets = 0
    list_of_tcp_pkts_time = list()
    list_of_udp_pkts_time = list()

    #time stamp as key and packet as value


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

    for timestamp, packet in input_data:
        number_of_packets = number_of_packets+1

        ether = dpkt.ethernet.Ethernet(packet)
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)

        ether = dpkt.ethernet.Ethernet(packet)

        if ether.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip= ether.data
        ipAddr= inet_to_str(ip.dst)

        if ipAddr != target_ip:
            continue
        
        if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                dport = tcp.dport
                list_of_tcp_pkts_time.append([time_string, ip])


        elif ip.p==dpkt.ip.IP_PROTO_UDP: # Check for UDP packets
                list_of_udp_pkts_time.append([time_string, ip])



    list_of_tcp_port= sorted(list_of_tcp_pkts_time, key=lambda x: x[1].data.dport)
    list_of_udp_port= sorted(list_of_udp_pkts_time, key=lambda x: x[1].data.dport)        

        #for loop for TCP scans
    list_of_list_of_tcp_scans = list()
    j=0
    while j < len(list_of_tcp_port):
        i=j+1
        temp_tcp_scan= list()
        #temp_tcp_scan.append(list_of_tcp_port[j])
        while i < len(list_of_tcp_port) - 1:
            if(list_of_tcp_port[i][1].data.dport - list_of_tcp_port[j][1].data.dport <= W_s):
                if len(temp_tcp_scan) == 0:
                    temp_tcp_scan.append(list_of_tcp_port[j])
                temp_tcp_scan.append(list_of_tcp_port[i])
                if i == len(list_of_tcp_port) - 2 and list_of_tcp_port[i+1][1].data.dport - list_of_tcp_port[i][1].data.dport <= W_s:
                    temp_tcp_scan.append(list_of_tcp_port[i+1])
            else:
                break
            j=i
            i = i+1
        if len(temp_tcp_scan) >= N_s:
            list_of_list_of_tcp_scans.append(temp_tcp_scan)
        j=i 
    
    

        #for loop for TCP probes
    list_of_list_of_tcp_probes = list()
    checked_port = list()
    for y in list_of_tcp_pkts_time:
        i=0
        port_num = y[1].data.dport
        temp_port_num_list = list()
        #temp_port_num_list.append([y[0], y[1]])
        if (y[1].data.dport) in checked_port:
            continue
        else:    
            checked_port.append(y[1].data.dport)
            length = 1
            i = 0
            while i < len(list_of_tcp_pkts_time):
                if(y[1].data.dport == list_of_tcp_pkts_time[i][1].data.dport):
                    temp_port_num_list.append([list_of_tcp_pkts_time[i][0], list_of_tcp_pkts_time[i][1]])
                    #print(list_of_tcp_pkts_time[i][1].data.dport)
                    length = length+1
                i=i+1
                    

        j = 0
        while j < len(temp_port_num_list)-1:
            temp_tcp_probe = list()
            count_in_probe = 1
            while j < len(temp_port_num_list)-1 and temp_port_num_list[j+1][0] - temp_port_num_list[j][0] < datetime.timedelta(seconds= W_p): 
                if count_in_probe == 1:
                    temp_tcp_probe.append(temp_port_num_list[j])
                temp_tcp_probe.append(temp_port_num_list[j+1])
                count_in_probe = count_in_probe + 1
                j=j+1

            if count_in_probe >= N_p:
                list_of_list_of_tcp_probes.append(temp_tcp_probe)
                
            j=j+1           
                
            

        #for loop for UDP scans
    list_of_list_of_udp_scans = list()
    j=0
    while j < len(list_of_udp_port):
        i=j+1
        temp_udp_scan= list()
        while i < len(list_of_udp_port) - 1:
            if(list_of_udp_port[i][1].data.dport - list_of_udp_port[j][1].data.dport <= W_s):
                if len(temp_udp_scan) == 0:
                    temp_udp_scan.append(list_of_udp_port[j])
                temp_udp_scan.append(list_of_udp_port[i])
                if i == len(list_of_udp_port) - 2 and list_of_udp_port[i+1][1].data.dport - list_of_udp_port[i][1].data.dport <= W_s:
                    temp_udp_scan.append(list_of_udp_port[i+1])
            else:
                break
            j=i
            i = i+1
        if len(temp_udp_scan) >= N_s:
            list_of_list_of_udp_scans.append(temp_udp_scan)
        j=i 


        #for loop for UDP probes
    list_of_list_of_udp_probes = list()
    checked_port = list()
    for y in list_of_udp_pkts_time:
        i=0
        port_num = y[1].data.dport
        temp_port_num_list = list()
        #temp_port_num_list.append([y[0], y[1]])
        if (y[1].data.dport) in checked_port:
            continue
        else:    
            checked_port.append(y[1].data.dport)
            length = 1
            i = 0
            while i < len(list_of_udp_pkts_time):
                if(y[1].data.dport == list_of_udp_pkts_time[i][1].data.dport):
                    temp_port_num_list.append([list_of_udp_pkts_time[i][0], list_of_udp_pkts_time[i][1]])
                    #print(list_of_tcp_pkts_time[i][1].data.dport)
                    length = length+1
                i=i+1
                    

        j = 0
        while j < len(temp_port_num_list)-1:
            temp_udp_probe = list()
            count_in_probe = 1
            while j < len(temp_port_num_list)-1 and temp_port_num_list[j+1][0] - temp_port_num_list[j][0] < datetime.timedelta(seconds= W_p): 
                if count_in_probe == 1:
                    temp_udp_probe.append(temp_port_num_list[j])
                temp_udp_probe.append(temp_port_num_list[j+1])
                count_in_probe = count_in_probe + 1
                j=j+1

            if count_in_probe >= N_p:
                list_of_list_of_udp_probes.append(temp_udp_probe)
                
            j=j+1  


    print("CS 352 Wireshark (Part 2)")
    print("Reports for TCP")
    x = len(list_of_list_of_tcp_probes)
    print "Found",  x,  "probes" 
    for x in list_of_list_of_tcp_probes:
        i=0
        print "Probe: [" + str(len(x)) + " Packets]"
        for y in x:
            print "\t", "Packet [Timestamp: " + str(x[i][0]) + ", Port: " + str(x[i][1].data.dport) + ", Source IP: " + inet_to_str(x[i][1].src) + "]"     
            i=i+1
         
    
    print "Found", len(list_of_list_of_tcp_scans), "scans"
    for x in list_of_list_of_tcp_scans:
        i=0
        print  "Scan: [" + str(len(x)) + " Packets]"
        for y in x:
            print "\t", "Packet [Timestamp: " + str(x[i][0]) + ", Port: " + str(x[i][1].data.dport) + ", Source IP: " + inet_to_str(x[i][1].src) + "]"       
            i=i+1
          

    print "Reports for UDP"
    print "Found", len(list_of_list_of_udp_probes), "probes"
    for x in list_of_list_of_udp_probes:
        i=0
        print "Probe: [" + str(len(x)) + " Packets]"
        for y in x:
            print "\t", "Packet [Timestamp: " + str(x[i][0]) + ", Port: " + str(x[i][1].data.dport) + ", Source IP: " + inet_to_str(x[i][1].src) + "]"    
            i=i+1
        
                
    print "Found", len(list_of_list_of_udp_scans), "scans"       
    for x in list_of_list_of_udp_scans:
        i=0
        print "Scan: [" + str(len(x)) +" Packets]"
        for y in x:
            print "\t", "Packet [Timestamp: " + str(x[i][0]) + ", Port: " + str(x[i][1].data.dport) + ", Source IP: " + inet_to_str(x[i][1].src) + "]"        
            i=i+1
        


# execute a main function in Python
if __name__ == "__main__":
    main()

 

    