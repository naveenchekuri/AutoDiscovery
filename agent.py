import nmap
from netaddr import IPNetwork, IPAddress
import requests
from msc import entity
import socket
import netifaces
import sys
import struct
import ctypes

ping_packet = "\x06\x00\xff\x06\x00\x00\x11\xbe\x80\x00\x00\x00"
udp_timeout = 10
sport = 8238
dport = 623
ip_hdr_fmt = '!BBHHHBBH4s4s'
eth_hdr_fmt = '!6s6sH'

# Max number of packets we want to process. 
# Increase this in case of highly congested network or hops.
no_other_packets = 40 

"""This class defines discovery agent in Galileo"""
class DiscovAgent:

    """Init function"""
    def __init__(self, raw_sock=None, udp_sock=None):
        if raw_sock is None:
            self.raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        else:
            self.raw_sock = raw_sock

        if udp_sock is None:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.udp_sock.settimeout(udp_timeout)
        else:
            self.udp_sock = udp_sock

        self.ntwk_intf_bdcast = []
        self.ntwk_intf_mac = []
        self.ntwk_intf_ip = []
        self.ntwk_intf_name = []
        self.ipmi_ip = []
        self.ipmi_mac = []

    """Get Network interface name, ip, broadcast address and mac address"""
    def get_interfaces(self):
        for interface in netifaces.interfaces():
            link = netifaces.ifaddresses(interface)
            if link.has_key(netifaces.AF_INET):
                t_link = link[netifaces.AF_INET]
                packet_link = link[netifaces.AF_PACKET]
                for tmp_link in t_link:
                    if 'broadcast' in tmp_link:
                        self.ntwk_intf_name.append(interface)
                        self.ntwk_intf_ip.append(tmp_link['addr'])
                        self.ntwk_intf_bdcast.append(tmp_link['broadcast'])
                        for tp_link in packet_link:
                            if 'addr' in tp_link:
                                self.ntwk_intf_mac.append(tp_link['addr'])
        
    """Bind the raw socket"""
    def bind(self, intf_name):
        try:
            self.raw_sock.bind((intf_name,socket.SOCK_RAW))
            print "Bind to raw socket successful!"
        except socket.error , msg:
            print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

    """Build UDP Header. Don't worry about IP header unless we want 
    to send a raw packet. Header typically is of this format unless
    TCP/IP model is changed
    -----------------------------------------------------------------
    | 16-bit source port number  |   16-bit destination port number |
    -----------------------------------------------------------------
    | 16-bit UDP length          |   16-bit UDP checksum            |
    -----------------------------------------------------------------
    |                      data                                     |
    -----------------------------------------------------------------
    We pack in source port, destination port and length (includes header
    and data). Checksum is set to NULL as its optional for ipv4. Change
    this when ipv6 is supported by Galileo
    """
    def build_udp_packet(self, sport, dport, data):
        # Calculate the length 
        udp_len = 8 + len(data)
    
        # Pack in the header data and add checksum
        begin = struct.pack('HHH', sport, dport, udp_len)
        packet = begin + '\000\000' + data

        # Convert the packet to Network Big endian
        rt_packet = self.__htons(packet[0:2]) + self.__htons(packet[2:4]) + self.__htons(packet[4:6]) + packet[6:]
        return rt_packet

    """ Pack the header data as short with Big endian"""
    def __htons(self, s):
        return struct.pack('!H', struct.unpack('H', s)[0])

    """ Build IP packet. Standard IP header is a follows. We would wrap
    the UDP packet built using above in to the IP payload. This is just
    and IPV4 packet.
    -----------------------------------------------------------------
    |Version|  IHL  |Type of Service|          Total Length         |
    -----------------------------------------------------------------
    |         Identification        |Flags|      Fragment Offset    |
    -----------------------------------------------------------------
    |  Time to Live |    Protocol   |         Header Checksum       |
    -----------------------------------------------------------------
    |                       Source Address                          |
    -----------------------------------------------------------------
    |                    Destination Address                        |
    -----------------------------------------------------------------
    |                    Options                    |    Padding    |
    -----------------------------------------------------------------
    Change this packet header when IPV6 is supported in Galileo. We pack
    in source and destination IP addresses with no options or padding
    """
    def build_ip_packet(self, srcaddr, dstaddr, udp_packet):
        ip_buf = ctypes.create_string_buffer(struct.calcsize(ip_hdr_fmt))
        ip_ihl = 69
        ip_tlen = 20 + len(udp_packet)
        """ If you are changing the following fields. Make sure you know what
            you are doing.

            ipbuf - Buffer to store the packet
            0 - IPV4 version
            ip_ihl - Header length (change this if you are adding options etc)
            0 - No ECN or DSCP
            ip_tlen - Total length of packet including data
            15213 - unique identifier (feel free to change this)
            16384 - No flag and fragmentation not needed
            64 -TTL
            socket.IPPROTO_UDP - UDP protocol
            0 - Lets fill the check sum later
            srcaddr - source address
            dstaddr - destination address
        """
        struct.pack_into('!BBHHHBBH4s4s', ip_buf, 0,
                  ip_ihl, 0, ip_tlen,
                  15213, 16384,
                  64, socket.IPPROTO_UDP,
                  0,
                  srcaddr, dstaddr)

        # Get the check sum of the header now and pack it in
        ip_cksum = self.construct_ipv4_checksum(ip_buf.raw)
        struct.pack_into('!H', ip_buf, struct.calcsize(ip_hdr_fmt[:8]),
                  ip_cksum)
  
        # Pack in header and data
        ip_datagram = ''.join([ip_buf.raw, udp_packet])
        return ip_datagram

    """ Construct IPV4 checksum """
    def construct_ipv4_checksum(self, data):
        sum = 0
        for i in range(0, len(data), 2):
            if i < len(data) and (i + 1) < len(data):
                sum += (ord(data[i]) + (ord(data[i + 1]) << 8))
            elif i < len(data) and (i + 1) == len(data):
                sum += ord(data[i])
        addon_carry = (sum & 0xffff) + (sum >> 16)
        result = (~ addon_carry) & 0xffff
        result = result >> 8 | ((result & 0x00ff) << 8)
        return result

    """ Build Ethernet Frame. This is the easiest among the three
    -----------------------------------------------------------------
    | 14 byte source mac address |  14 byte destination mac address |
    -----------------------------------------------------------------
    |                     Ethernet packet type                      |
    -----------------------------------------------------------------
    |                      data                                     |
    -----------------------------------------------------------------
    We pack in source mac, destination mac and packet type
    """
    def build_ethernet_frame(self, srcmac, dstmac, ip_packet):
        eth_header = struct.pack(eth_hdr_fmt, dstmac, srcmac, 0x0800)
        eth_frame = ''.join([eth_header, ip_packet])
        return eth_frame

    """ Construct the entire RMCP packet """
    def construct_rmcp_packet(self, srcmac, dstmac, srcip, dstip):
        udp_packet = self.build_udp_packet(sport, dport, ping_packet)
        src_inet_ip = socket.inet_aton(srcip)
        dst_inet_ip = socket.inet_aton(dstip)
        ip_packet = self.build_ip_packet(src_inet_ip, dst_inet_ip, udp_packet)
        src_octet = self.get_byte_repr_mac(srcmac)
        dst_octet = self.get_byte_repr_mac(dstmac)
        ethernet_frame = self.build_ethernet_frame(src_octet,dst_octet,ip_packet)
        return ethernet_frame

    """ Get byte representation of mac address"""
    def get_byte_repr_mac(self, mac):
        maclist = mac.split(':')
        mac_str = ''
        for octet in maclist:
            a = int(octet, 16)
            b = chr(a)
            mac_str = mac_str + b
        return mac_str

    """Send RMCP Ping packet. Lets play ping pong"""
    def send_rmcp_ping(self, ethernet_frame):
        try:
            sent_bytes = 0
            sent_bytes = self.raw_sock.send(ethernet_frame)
            if sent_bytes <= 0:
                print "Failed to send Packet!"
            return sent_bytes
        except Exception, e:
            print("Exception! pray that network is not congested %s'" % e)

    """Receive RMCP Pong"""
    def receive_rmcp_response(self):
        try:
            packet_count = 0 
            while True:
                data = self.raw_sock.recvfrom(4096)
                packet_data = data[0]
                # Check for other packets. Discard non UDP and non RMCP ones ones
                # 23, 11 - UDP, 42, 06 - RMCP
                if packet_data[23].encode('hex') != '11' or packet_data[42].encode('hex') != '06':
                    if packet_count > no_other_packets:
                        break
                    packet_count = packet_count + 1
                    continue

                # If it is an UDP or RMCP, check if it is broadcast
                if packet_data[6].encode('hex') == 'ff' or packet_data[26].encode('hex') == 'ff':
                    continue

                # If none of those, this is our holy grail
                self.unpack_data(packet_data)

        except Exception, e:
            print("Exception while receiving: %s " % e)

    def unpack_data(self, packet):
        hdr_len = struct.calcsize(eth_hdr_fmt)
        eth_header = struct.unpack(eth_hdr_fmt, packet[:hdr_len])
        self.ipmi_mac.append(eth_header[1])
        ip_data = packet[hdr_len:]
        ip_hdr_len = struct.calcsize(ip_hdr_fmt)
        ip_hdr = struct.unpack(ip_hdr_fmt, ip_data[:ip_hdr_len])
        self.ipmi_ip.append(ip_hdr[8])

"""Define discovery entity"""
def create_msc_entity():
    agent_ent = entity("discovery_agent", create_logging_handle())
    agent_ent.event(label="Created Discovery Agent Entity", begin=True)
    return agent_ent

x = DiscovAgent()
x.get_interfaces()
for index, bdcast_addr in enumerate(x.ntwk_intf_bdcast):

    print "Identifying nodes on interface: " + x.ntwk_intf_name[index] + "..."
    # Bind the socket to interface
    x.bind(x.ntwk_intf_name[index])

    print "Constructing broadcast Ping Packet ..."
    # Lets construct the packet. We are broadcasting 
    ethernet_frame = x.construct_rmcp_packet(x.ntwk_intf_mac[index], "ff:ff:ff:ff:ff:ff", x.ntwk_intf_ip[index], bdcast_addr)

    print "Perform a broadcast ping ..."   
    x.send_rmcp_ping(ethernet_frame)

    print "Waiting for response ..."
    x.receive_rmcp_response()

    print "Got data: %s" % ':'.join(x.encode('hex') for x in x.ipmi_ip[index])
    print "Got data: %s" % ':'.join(x.encode('hex') for x in x.ipmi_mac[index])
