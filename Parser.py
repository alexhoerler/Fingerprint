import dpkt
import sys

# get both the IP and TCP source and destination addresses
# If the frame doesn't contain a IP or TCP packet, print so
# packet_cap: a string name of the packet capture
def get_ip_tcp_head(packet_cap):
    file = open(packet_cap)
    pcap = dpkt.pcap.Reader(file)
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        # get the IP level data
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            print("Not an instance of IPv4. Can't extract data.")
            continue
        else:
            print("IP Packet: %s => %s" % (inet_to_str(ip.src), inet_to_str(ip.src)))

        #get the TCP level data
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            print("Not an instance of TCP. Can't extract data past the IP level.")
            continue
        else:
            print("TCP Packet: %s => %s" % (tcp.sport, tcp.dport))

    file.close()

# gets the source and destination MAC addresses
# packet_cap: a string name of the packet capture
def get_eth_head(packet_cap):
    file = open(packet_cap)
    pcap = dpkt.pcap.Reader(file)
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        print("Ethernet Frame: %s => %s" % (mac_addr(eth.src), mac_addr(eth.dst)))

    file.close()


def main(argv):
    for pcap in argv:
        get_ip_tcp_head(pcap)

if __name__ == "__main__":
    main(sys.argv[1:])
