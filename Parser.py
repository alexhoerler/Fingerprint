import dpkt
import struct
import hashlib
import datetime
import socket
import sys
import re
from dpkt.compat import compat_ord

# dictionary that contains a list of packets for every protocol connection
# follows the format:
# { (protocol, ip source, ip destination, source port, destination port) : {"ja3": ja3, "ja3s": ja3s, "length": length} }
# ja3 and ja3s only included for tcp connections
sessions = {}

# the code for the tls handshake
TLS_HANDSHAKE = 22

# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}


def update_sessions(packet_cap):
    """ Updates the sessions dictionary with packets from the packet_cap file

    :param packet_cap: the file name with the packets
    """

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
                # indicates it contains a tcp packet
                ip = eth.data
                ip_payload = ip.data

                key = tuple_to_key(tuple)
                if key[0] == "TCP":
                    sessions.setdefault(key, {"ja3": None, "ja3s": None, "length": 0})
                elif key[0] == "UDP":
                    sessions.setdefault(key, {"length": 0})

                # stores ip payload length
                bytes_transferred = ip.len - ip.hl
                sessions[key]["length"] += bytes_transferred

                # tracks and stores the ja3 and ja3s
                if isinstance(ip_payload, dpkt.tcp.TCP):
                    tls_packet = list()
                    try:
                        tls_packet, bytes_used = dpkt.ssl.tls_multi_factory(ip_payload.data)
                    except dpkt.ssl.SSL3Exception:
                        continue
                    except dpkt.dpkt.NeedData:
                        continue

                    if len(tls_packet) <= 0:
                        continue

                    for tls_record in tls_packet:
                        if len(tls_record.data) == 0:
                            continue
                        hashed_ja3 = None
                        hashed_ja3s = None
                        if tls_record.type == TLS_HANDSHAKE:
                            try:
                                handshake = dpkt.ssl.TLSHandshake(tls_record.data)
                            except dpkt.dpkt.NeedData:
                                continue
                            tls_pkt = handshake.data
                            if isinstance(tls_pkt, dpkt.ssl.TLSClientHello):
                                ja3 = get_ja3(tls_pkt)
                                hashed_ja3 = hashlib.md5(ja3.encode()).hexdigest()
                                sessions[key]["ja3"] = hashed_ja3
                            elif isinstance(tls_pkt, dpkt.ssl.TLSServerHello):
                                ja3s = get_ja3s(tls_pkt)
                                hashed_ja3s = hashlib.md5(ja3s.encode()).hexdigest()
                                sessions[key]["ja3s"] = hashed_ja3s


def get_tuple(eth):
    """ Gets the necessary 5 tuple key for the sessions dictionary

    :param eth: the ethernet frame to examine
    :return: the 5 tuple with protocol, source, and destination addresses; or None if necessary
    """

    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        print("Not an instance of IPv4. Can't extract data.\n")
        return None
    else:
        print("IP Packet: %s => %s" % (inet_to_str(ip.src), inet_to_str(ip.dst)))

    ip_payload = ip.data
    if isinstance(ip_payload, dpkt.tcp.TCP):
        print("TCP Packet: %d => %d\n" % (ip_payload.sport, ip_payload.dport))
        return ("TCP", ip.src, ip.dst, ip_payload.sport, ip_payload.dport)
    elif isinstance(ip_payload, dpkt.udp.UDP):
        print("UDP Packet: %d => %d\n" % (ip_payload.sport, ip_payload.dport))
        return ("UDP", ip.src, ip.dst, ip_payload.sport, ip_payload.dport)
    else:
        print("Not an instance of TCP or UDP. Can't extract data\n")
        return None



def tuple_to_key(tuple):
    """ Turns the 5 tuple of addresses into the key 5 tuple
    Makes sure that both outgoing and incoming packets have the same key

    :param tuple: a 5 tuple of the protocol, and source and destination addresses for IP and TCP/UDP
    :return: a 5 tuple key for the session dictionary
    """

    if tuple[1] == tuple[2]:
        if tuple[3] > tuple[4]:
            return tuple
        else:
            key = (tuple[0], tuple[1], tuple[2], tuple[4], tuple[3])
            return key
    elif tuple[1] > tuple[2]:
        return tuple
    else:
        key = (tuple[0], tuple[2], tuple[1], tuple[4], tuple[3])
        return key


def get_ja3(client_hello):
    """ Gets the ja3 from the TLS client hello packet

    :param client_hello: The client hello packet in bytes
    :return: The string ja3
    """

    ja3_list = list()
    ja3_list.append(str(client_hello.version))
    buf, ptr = dpkt.ssl.parse_variable_array(client_hello.data, 1)
    buf, ptr = dpkt.ssl.parse_variable_array(client_hello.data[ptr:], 2)
    ja3_list.append(make_ja3_segment(buf, 2))
    ja3_list += get_ja3_extensions(client_hello)
    ja3 = ",".join(ja3_list)

    return ja3


def make_ja3_segment(data, element_width):
    """ Converts an array of elements into the corresponding ja3 segment string format

    :param data: bytes in the buffer
    :param element_width: byte count to increment over
    :return: string of the ja3 segment
    """

    int_values = list()
    data = bytearray(data)
    if len(data) % element_width:
        raise ValueError("%d is not a multiple of the width (%d)" % (len(data), element_width))

    for i in range(0, len(data), element_width):
        element = network_to_host(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_values.append(element)

    return "-".join(str(element) for element in int_values)


def network_to_host(buf):
    """ Converts Network Order to Host Order (Big endian to Little endian)

    :param buf: bytes to convert
    :return: an integer value of ...
    """

    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack("!H", buf)[0]
    elif len(buf) == 4:
        return struct.unpack("!I", buf)[0]
    else:
        raise ValueError("Input buffer size is invalid for network to host")


def get_ja3_extensions(handshake):
    """ Process the extensions in the handshake and convert them to ja3 segments

    :param handshake: TLSHandshake packet (Client Hello)
    :return: list of 3 components [Extensions, Elliptic Curves, Elliptic Curve Point Formats]
    """

    # dpkt.TLSClientHello only has extensions attribute if the packet is long enough
    if not hasattr(handshake, "extensions"):
        return ["", "", ""]

    extensions = list()
    elliptic_curves = ""
    ec_point_formats = ""
    for ext_value, ext_data in handshake.extensions:
        if not GREASE_TABLE.get(ext_value):
            extensions.append(ext_value)
        if ext_value == 0x0a:
            # 0x0a indicates Elliptic Curve Extension
            bytes, position = dpkt.ssl.parse_variable_array(ext_data, 2)
            # Elliptic Curves are 16 bit values
            elliptic_curves = make_ja3_segment(bytes, 2)
        elif ext_value == 0x0b:
            # 0x0b indicates Elliptic Curve Point Format Extension
            bytes, position = dpkt.ssl.parse_variable_array(ext_data, 1)
            # Elliptic Curve Point Formats are 8 bit values
            ec_point_formats = make_ja3_segment(bytes, 1)
        else:
            continue

    extension_segments = list()
    extension_segments.append("-".join([str(element) for element in extensions]))
    extension_segments.append(elliptic_curves)
    extension_segments.append(ec_point_formats)
    return extension_segments


def get_ja3s(server_hello):
    """ Gets the ja3s from the TLS server hello packet

    :param server_hello: The server hello packet in bytes
    :return: The string ja3s
    """

    ja3s_list = list()
    ja3s_list.append(str(server_hello.version))
    ja3s_list.append(str(server_hello.cipher_suite))
    ja3s_list += get_ja3s_extensions(server_hello)
    ja3s = ",".join(ja3s_list)

    return ja3s


def get_ja3s_extensions(handshake):
    """ Process the extensions in the handshake and convert them to ja3s segment

    :param handshake: TLSHandshake packet (Server hello)
    :return: extensions string
    """

    # dpkt.TLSServerHello only has extensions attribute if the packet is long enough
    if not hasattr(handshake, "extensions"):
        return [""]

    extensions_list = list()
    for ext_value, ext_data in handshake.extensions:
        extensions_list.append(ext_value)

    extensions = list()
    extensions.append("-".join(str(element) for element in extensions_list))
    return extensions


def mac_addr(address):
    """ Convert a MAC address to a readable/printable string
    Taken from the dpkt website

    :param address: a string MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
    :returns: readable string of MAC address
    """

    return ":".join("%02x" % compat_ord(b) for b in address)


def inet_to_str(inet):
    """ Convert an internet object to a string
    Taken from the dpkt website

    :param inet: internet object
    :return: an IP address string
    """

    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def get_all_head(packet_cap):
    """ Get the ethernet, IP and TCP/UDP source and destination addresses
    If the frame doesn't contain a IP or TCP/UDP packet, print so

    :param packet_cap: a string name of the packet capture
    """

    file = open(packet_cap, "rb")
    if re.search(r"\.pcap$", packet_cap):
        pcap = dpkt.pcap.Reader(file)
    elif re.search(r"\.pcapng$", packet_cap):
        pcap = dpkt.pcapng.Reader(file)
    else:
        raise ValueError("Invalid file type: %s" % (packet_cap))

    packet_num = 1
    for timestamp, buf in pcap:
        print("\n%d. Timestamp: %s" % (packet_num, str(datetime.datetime.utcfromtimestamp(timestamp))))
        packet_num += 1
        eth = dpkt.ethernet.Ethernet(buf)
        print("Ethernet Frame: %s => %s" % (mac_addr(eth.src), mac_addr(eth.dst)))

        # get the IP level data
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            print("Not an instance of IPv4. Can't extract data.")
            continue
        else:
            print("IP Packet: %s => %s" % (inet_to_str(ip.src), inet_to_str(ip.dst)))

        #get the TCP level data
        ip_payload = ip.data
        if isinstance(ip_payload, dpkt.tcp.TCP):
            print("TCP Packet: %d => %d" % (ip_payload.sport, ip_payload.dport))
        elif isinstance(ip_payload, dpkt.udp.UDP):
            print("UDP Packet: %d => %d" % (ip_payload.sport, ip_payload.dport))
        else:
            print("Not an instance of TCP or UDP. Can't extract data")


    file.close()


def print_sessions():
    """ Prints sessions in a readable string format
    """
    session_num = 1
    for connection, attributes in sessions.items():
        print("\nSession %d" % session_num)
        print("Type: %s, IP source: %s, IP destination: %s, Source port: %d, Destination port: %d" %
              (connection[0], inet_to_str(connection[1]), inet_to_str(connection[2]), connection[3], connection[4]))
        session_num += 1
        for key, value in attributes.items():
            print("%s: %s" % (key, value))


def main(argv):
    for pcap in argv:
        update_sessions(pcap)

    print_sessions()

if __name__ == "__main__":
    main(sys.argv[1:])
