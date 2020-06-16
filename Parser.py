import dpkt

def main(argv):
    pass

if __name__ == "__main__":
    main(sys.argv[1:])


# gets both the IP and TCP source and destination addresses
# If the frame doesn't contain a IP or TCP packet, print so
# input is a string name of the packet capture
def getIpTcpHead(packet_cap):
    frame = open(packet_cap)
    pcap = dpkt.pcap.Reader(frame)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        ip = eth.data
        print('IP Packet: %s => %s' % (inet_to_str(ip.src), inet_to_str(ip.src)))

        tcp = ip.data
        print('TCP Packet: %s => %s' % (tcp.sport, tcp.dport))

    frame.close()

# gets the source and destination MAC addresses
# input is a string name of the packet capture
def getEthHead(packet_cap):
    frame = open(packet_cap)
    pcap = dpkt.pcap.Reader(frame)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: %s => %s' % (mac_addr(eth.src), mac_addr(eth.dst)))

    frame.close()