import time
import socket
import sys 
    

def lookUpDns(hostname):
    # gets a string with the hostname and return the ip-address as a string
    # hostnome must be in this structure: 'www.hostname.ending' or 'hostname.ending'
    
    # Try and except structure to catch problems if the hostname does not exist
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except:
        print('Cannot resolve hostname: Name or service not known')
        return False
    

def icmp_checksum(package):
    # calculates the checksum for the icmp header
    # takes the checksum and adds it with the next remaining byte-element of the icmp_header
    # seperate the string and make a 16 bit field by matching two bytes fields into one  
    package_list = [str(package[i:i+1].hex()+ package[i+1:i+2].hex()) \
                   for i in range(0, len(package), 2)]
    # Adding the 16 bit values one by one
    checksum = 0
    for bit16 in package_list:
        checksum += int(bit16, 16)
        
        # Prevent bit overflow
        if checksum > 65535:
            checksum -= 65536
            checksum += 1
            
    # One's complement
    return (~checksum) & 0xFFFF


def ping_request(ip_address, stats, icmp_ident, icmp_seq, ttl):
    # Send a ping request
    # Function flow: 
    # 1. Create a package with the checksum 0 to calculate the real value of checksum
    # 2. Create the package for sending: Consisting out of icmp header and icmp data (random)
    # 3. Create the raw socket
    # 4. Send the package
    # 5. Wait for the receiving package
    # 6. Update Stats
    
    # Create icmp_package for sending: Code = 8, Checksum = 0 for calculating the right checksum value
    # all values are bytes
    icmp_header = ICMPHeader(8, 0, 0, icmp_ident, icmp_seq)
    header = icmp_header.get_header()
    icmp_data = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    checksum = icmp_checksum(header + icmp_data)
    
    # Now build the package with the right checksum
    # use htons to synchronize with network byte order
    icmp_header = ICMPHeader(8, 0, socket.htons(checksum), icmp_ident, icmp_seq)
    header = icmp_header.get_header()
    package = header + icmp_data

    # Build the socket
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Set the ttl value of the ip header
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    except:
        print('Need root privileges to run this script!')
        print('If the program is not running with root privileges either, an error accessing the network socket occured!')
        raise SystemExit
    
    # Connect to the server/host
    raw_socket.sendto(package, (ip_address, 1))
    start_time = time.time()
    
    # Update stats that a package has been sent
    stats.update_sent()
    
    # Wait for the request, request.timeout is set to 2s
    raw_socket.settimeout(2)
    try:
        # try to catch package
        package, ip_address = raw_socket.recvfrom(2048)
        raw_socket.close()
        # if package received, stop the time
        stop_time = time.time()
        
        # extract the ipv4 header
        ipv4_header = package[0:20]
        version = ipv4_header[0]
        tos = ipv4_header[1]
        length = socket.htons(int(str(ipv4_header[2:3].hex()+ipv4_header[3:4].hex()), 16))
        identification = socket.htons(int(str(ipv4_header[4:5].hex()+ipv4_header[5:6].hex()), 16))
        foo = socket.htons(int(str(ipv4_header[6:7].hex()+ipv4_header[7:8].hex()), 16))
        ttl = ipv4_header[8]
        protocol = ipv4_header[9]
        check = socket.htons(int(str(ipv4_header[10:11].hex()+ipv4_header[11:12].hex()), 16))
        sou = str(ipv4_header[12]) + '.' + str(ipv4_header[13]) + '.' + str(ipv4_header[14]) + '.' + str(ipv4_header[15])
        dest = str(ipv4_header[16]) + '.' + str(ipv4_header[17]) + '.' + str(ipv4_header[18]) + '.' + str(ipv4_header[19])
        ipv4 = IPv4Header(version, tos, length, identification, foo, ttl, protocol, check, sou, dest)
        
        # extract the icmp-header and icmp-data to get data like identifier, sequence and type of service
        icmp_header = package[20:28]
        icmp_data = package[28:]
        
        # Get the type of service
        tos_icmp = icmp_header[0]
        
        # Test if type of service is an echo
        if tos_icmp == 0:
            code = icmp_header[1]
            checksum = socket.htons(int(str(icmp_header[2:3].hex()+icmp_header[3:4].hex()), 16))
            identifier = socket.htons(int(str(icmp_header[4:5].hex()+icmp_header[5:6].hex()), 16))
            sequence = socket.htons(int(str(icmp_header[6:7].hex()+icmp_header[7:8].hex()), 16))
            icmp = ICMPHeader(tos_icmp, code, checksum, identifier, sequence)
            
            # Checksum Test
            icmp_dummy = ICMPHeader(tos_icmp, code, 0, identifier, sequence)
            checksum_test = socket.htons(icmp_checksum(icmp_dummy.get_header()+icmp_data))
            if checksum_test != checksum:
                print('Packet is not Valid')
                return 0
            
            # Test the identifier
            if identifier == icmp_ident:
                # register that the echo is received
                stats.update_received()
                # calculate the rtt time in ms
                rtt = (stop_time-start_time)*1000
                # write the rtt
                stats.new_time(rtt)
                return (rtt, ipv4, icmp, ip_address)
            
        elif tos_icmp == 11:
            # TTL exceeded code is 11
            print('Time-to-live (TTL) exceeded')
            return 0
        else:
            print('timeout reached')
            return 0
    except KeyboardInterrupt:
        raise SystemExit
    except:
        print('timeout reached')
        return 0



###############################################################################################################################
# Class Object for storing headers and stats                                                                                  #
###############################################################################################################################
    
class IPv4Header():
    # Class to save the informations of the IPv4 Header
    def __init__(self, version, tos, length, identification, foo, ttl, protocol, checksum, source, destination):
        self.version = version
        self.tos = tos
        self.length = length
        self.identification = identification
        self.foo = foo
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.source = source
        self.destination = destination
    
    def get_ttl(self):
        return self.ttl
    
    def get_length(self):
        return self.length
    
class ICMPHeader():
    # Class to save the informations of the ICMP Header
    
    # Variables:  Information                                                      Size 
    # tos:        Type of message: 8 = Echo ping request, 0 = Echo ping reply      1 Byte 
    # code:       Code number: 0 for Echo                                          1 Byte
    # checksum:   Checksum of the header                                           2 Byte
    # identifier: ICMP Identifier                                                  2 Byte
    # sequence:   ICMP Sequence number                                             2 Byte
    
    # __init__ Funktion
    def __init__(self, tos, code, checksum, identifier, sequence):
        self.tos = tos
        self.code = code
        self.checksum = checksum
        self.identifier = identifier
        self.sequence = sequence 
    
    # get sequence number
    def get_sequence(self):
        return self.sequence
    
    # return the header as a byte package
    def get_header(self):
        self.tos_byte = self.tos.to_bytes(1, byteorder = 'little')
        self.code_byte = self.code.to_bytes(1, byteorder = 'little')
        self.checksum_byte = self.checksum.to_bytes(2, byteorder = 'little')
        self.identifier_byte = self.identifier.to_bytes(2, byteorder = 'little')
        self.sequence_byte = self.sequence.to_bytes(2, byteorder = 'little')
        self.header = self.tos_byte + self.code_byte + self.checksum_byte + self.identifier_byte + self.sequence_byte
        return self.header
        
        
class FinalResults():
    # class that contains Variables, which should be displayed after terminating the Programm with crtl+C
    
    # Variables:
    # packets_sent:     counts the packages that has been sent
    # packets_received: counts the packages that has been received
    # rtt_list:         list with the Round Trip Times 
    # rtt_min:          minium Round Trip Time
    # rtt_avg:          average Round Trip Time
    # rtt_max:          maxmium Round Trip Time
    # rtt_stddev:       standard deviation of Round Trip Time
    
    def __init__(self):
        self.packets_sent = 0
        self.packets_received = 0
        self.rtt_list = []
        self.rtt_min = 0
        self.rtt_avg = 0
        self.rtt_max = 0
        self.rtt_stddev = 0
    
    # Append a new rtt value to the list rtt_list
    def new_time(self, rtt_value):
        self.rtt_list.append(rtt_value)
    
    # Calculate the maxium Round Trip Time
    def calculate_max(self):
        self.rtt_max = max(self.rtt_list)
      
    # Calculate the minimum Round Trip Time
    def calculate_min(self):
        self.rtt_min = min(self.rtt_list)
        
    # Calculate the average Round Trip Time
    def calculate_average(self):
        self.rtt_avg = sum(self.rtt_list)/len(self.rtt_list)
    
    # Calculate the standard deviation of the Round Trip Time
    def calculate_stddev(self):
        self.rtt_stddev = 0
        for i in self.rtt_list:
            self.rtt_stddev += (i-self.rtt_avg)**2/len(self.rtt_list)
    
    # Increase sent packages
    def update_sent(self):
        self.packets_sent += 1
    
    # Increase received packages
    def update_received(self):
        self.packets_received += 1
        
    # str builtin function
    def __str__(self):
        # try-accept to avoid division by zero
        try:
            self.calculate_average()
            self.calculate_max()
            self.calculate_min()
            self.calculate_stddev()
            return (str(self.packets_sent) + ' packet(s) transmitted, ' + \
                    str(self.packets_received) + ' packet(s) received, ' + \
                    str(100-100*self.packets_received/self.packets_sent) + '% packet loss\n' + \
                    'round-trip min/avg/max/stddev = ' + str('%3.3f'% self.rtt_min) + \
                    '/' + str('%3.3f'% self.rtt_avg) + '/' + str('%3.3f'% self.rtt_max) + \
                    '/' + str('%3.3f'% self.rtt_stddev) + ' ms')
        except:
            return(str(self.packets_sent) + ' packet(s) transmitted, ' + \
                    str(self.packets_received) + ' packet(s) received, ' + \
                    str(100-100*self.packets_received/self.packets_sent) + '% packet loss\n')
                
        
