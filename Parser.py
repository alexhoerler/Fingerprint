import dpkt
import datetime
import socket
import sys
import re
from dpkt.compat import compat_ord

# get both the IP and TCP source and destination addresses
# If the frame doesn't contain a IP or TCP packet, print so
# packet_cap: a string name of the packet capture
def get_ip_tcp_head(packet_cap):

    file = open(packet_cap, "rb")
    if re.search(r"\.pcap$", packet_cap):
        pcap = dpkt.pcap.Reader(file)
    elif re.search(r"\.pcapng$", packet_cap):
        pcap = dpkt.pcapng.Reader(file)
    else:
        raise ValueError("Invalid file type: %s" % (packet_cap))

    for timestamp, buf in pcap:
        print("Timestamp: %s" % str(datetime.datetime.utcfromtimestamp(timestamp)))
        eth = dpkt.ethernet.Ethernet(buf)

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

# gets the source and destination MAC addresses
# packet_cap: a string name of the packet capture
def get_eth_head(packet_cap):
    file = open(packet_cap, "rb")
    if re.search(r"\.pcap$", packet_cap):
        pcap = dpkt.pcap.Reader(file)
    elif re.search(r"\.pcapng$", packet_cap):
        pcap = dpkt.pcapng.Reader(file)
    else:
        raise ValueError("Invalid file type: %s" % (packet_cap))

    for timestamp, buf in pcap:
        print("Timestamp: %s" % str(datetime.datetime.utcfromtimestamp(timestamp)))
        eth = dpkt.ethernet.Ethernet(buf)
        print("Ethernet Frame: %s => %s\n" % (mac_addr(eth.src), mac_addr(eth.dst)))

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
        get_ip_tcp_head(pcap)

if __name__ == "__main__":
    main(sys.argv[1:])
