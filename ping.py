#!/usr/bin/env python

import sys
import time
from funktionen import *


# Aufruf des Scriptes muss in folgender Form erfolgen: scriptname hostname/IP-address
def main(hostname, ttl, statistic):
    
    # Try: If the hostname is valid and the function call is right, then proceed
    try:
        ip_address = lookUpDns(hostname)
        if ip_address == False:
            return 
        print('PING ' + str(hostname) + ' (' + str(ip_address) +'):')
    # except: terminate the program with an error message
    except:
        return('Incorrect input! Call the script in one of the following ways:\n'\
              + '1.) script.py [hostname] or 2.) script.py [ip_address]')
    # Set first identifier
    icmp_ident = 0
    
    # Set first sequenz number
    icmp_seq = 0
    
    # while-loop, sending pings as long as the user wishes -> interrupt with KeyboardInterrupt (Ctrl + c)
    while True:
        
        try:
            # send ping, gets back Round Trip Time (rtt), IPv4-Header and IPMC-Header
            (rtt, ipv4, icmp, server_ip) = ping_request(ip_address ,statistic, icmp_ident, icmp_seq, ttl)
        
            # format the Round Trip Time 
            rtt_str = str('%3.3f'% rtt)

            # get ICMP Sequence number
            icmp_seq_received = icmp.get_sequence()

            # get TTL value
            ttl = ipv4.get_ttl()

            print('Response from ' + str(server_ip[0]) + ': icmp_seq: ' + str(icmp_seq_received) + ', ttl: ' + \
                  str(ttl) + ', RTT: ' + rtt_str + 'ms')

            # increase identifiers
            icmp_ident += 1
            # increase icmp_seq number
            icmp_seq += 1
        except:
            icmp_ident += 1
            icmp_seq += 1
        # wait 1s to send another ping
        time.sleep(1)

    
    
if __name__ == "__main__":
    statistic = FinalResults()
    try:
        try: 
            # Optional argument: TTL
            ttl = 64
            if len(sys.argv) > 2:
                ttl = int(sys.argv[2])
            # call the main function
            main(sys.argv[1], ttl ,statistic)
        except KeyboardInterrupt:
            print('--- ' + str(sys.argv[1]) + ' ping statistics ---')
            print(statistic)
    except IndexError: 
        print('Call the script in one of the following ways:\n'\
              + '1.) script.py [hostname] [-optional:ttl] or 2.) script.py [ip_address] [-optional:ttl]')


        
