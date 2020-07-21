import dpkt
import datetime
import socket
import sys
import re
from dpkt.compat import compat_ord

# dictionary that contains a list of packets for every protocol connection
# follows the format:
# { (protocol, ip source, ip destination, tcp source, tcp destination) : [(timestamp, eth frame)] }
sessions = {}

# gets the necessary 5 tuple key for the sessions dictionary
# if the ethernet frame doesn't contain the right protocols, returns None
# eth: the ethernet frame to examine
# returns: the 5 tuple with protocol, source, and destination addresses; or None if necessary
def get_tuple(eth):
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        print("Not an instance of IPv4. Can't extract data.\n")
        return None
    else:
        print("IP Packet: %s => %s" % (inet_to_str(ip.src), inet_to_str(ip.dst)))

    tcp = ip.data
    if not isinstance(tcp, dpkt.tcp.TCP):
        print("Not an instance of TCP. Can't extract data past the IP level.\n")
        return None
    else:
        print("TCP Packet: %d => %d\n" % (tcp.sport, tcp.dport))
        return ("TCP", ip.src, ip.dst, tcp.sport, tcp.dport)


# updates the sesssions dictionary with packets from the packet_cap file
# packet_cap: the file name with the packets
def update_sessions(packet_cap):
    global sessions

    with open(packet_cap, "rb") as file:
        if re.search(r"\.pcap$", packet_cap):
            pcap = dpkt.pcap.Reader(file)
        elif re.search(r"\.pcapng$", packet_cap):
            pcap = dpkt.pcapng.Reader(file)
        else:
            raise ValueError("Invalid file type: %s" % (packet_cap))

        packet_num = 1
        for timestamp, buf in pcap:
            print("%d. Timestamp: %s" % (packet_num, str(datetime.datetime.utcfromtimestamp(timestamp))))
            packet_num += 1
            eth = dpkt.ethernet.Ethernet(buf)
            tuple = get_tuple(eth)
            if tuple is not None:
                key = tuple_to_key(tuple)
                sessions.setdefault(key, []).append((timestamp, eth))

# turns the 5 tuple of addresses into the key 5 tuple
# makes sure that both outgoing and incoming packets have the same key
# tuple: a 5 tuple of the protocol, and source and destination addresses for IP and TCP
# returns: a 5 tuple key for the session dictionary
def tuple_to_key(tuple):
    if tuple[1] == tuple[2]:
        if tuple[3] > tuple[4]:
            return tuple
        else:
            key = (tuple[0], tuple[1], tuple[2], tuple[4], tuple[3])
            return key
    elif tuple[1] > (tuple[2]):
        return tuple
    else:
        key = (tuple[0], tuple[2], tuple[1], tuple[4], tuple[3])
        return key

# prints sessions in a readable string format
def print_sessions():
    session_num = 1
    for key in sessions:
        print("Session %d: " % session_num)
        session_num += 1
        for timestamp, frame in sessions[key]:
            print("Timestamp: %s" % str(datetime.datetime.utcfromtimestamp(timestamp)))
            print("MAC: %s => %s" % (mac_addr(frame.src), mac_addr(frame.dst)))
            ip_packet = frame.data
            print("IP: %s => %s" % (inet_to_str(ip_packet.src), inet_to_str(ip_packet.dst)))
            tcp_packet = ip_packet.data
            print("TCP: %s => %s\n" % (tcp_packet.sport, tcp_packet.dport))


# get the ethernet, IP and TCP source and destination addresses
# If the frame doesn't contain a IP or TCP packet, print so
# packet_cap: a string name of the packet capture
def get_all_head(packet_cap):

    file = open(packet_cap, "rb")
    if re.search(r"\.pcap$", packet_cap):
        pcap = dpkt.pcap.Reader(file)
    elif re.search(r"\.pcapng$", packet_cap):
        pcap = dpkt.pcapng.Reader(file)
    else:
        raise ValueError("Invalid file type: %s" % (packet_cap))

    packet_num = 1
    for timestamp, buf in pcap:
        print("%d. Timestamp: %s" % (packet_num, str(datetime.datetime.utcfromtimestamp(timestamp))))
        packet_num += 1
        eth = dpkt.ethernet.Ethernet(buf)
        print("Ethernet Frame: %s => %s\n" % (mac_addr(eth.src), mac_addr(eth.dst)))

        # get the IP level data
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            print("Not an instance of IPv4. Can't extract data.\n")
            continue
        else:
            print("IP Packet: %s => %s" % (inet_to_str(ip.src), inet_to_str(ip.dst)))

        #get the TCP level data
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            print("Not an instance of TCP. Can't extract data past the IP level.\n")
            continue
        else:
            print("TCP Packet: %d => %d\n" % (tcp.sport, tcp.dport))

    file.close()


# taken from the dpkt website
# converts from a MAC address in hex form to a string
# address: MAC address string in hex form
# returns: MAC address string (readable)
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


# taken from the dpkt website
# converts an internet object to a string
# inet: internet object
# returns: a IP address string
def inet_to_str(inet):

    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def main(argv):
    for pcap in argv:
        update_sessions(pcap)

    print_sessions()

if __name__ == "__main__":
    main(sys.argv[1:])
