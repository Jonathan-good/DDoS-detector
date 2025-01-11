from scapy.all import *
import struct


def create_pcap_file(filename, dataset):
    custom_packets = []

    for data in dataset:
        # Define values for the features
        src = data[0]
        dst = data[1]
        pktcount = data[2]
        bytecount = data[3]
        dur = data[4]
        dur_nsec = data[5]
        pktrate = data[6]
        Protocol = data[7]
        port_no = data[8]
        tx_bytes = data[9]
        rx_bytes = data[10]


        # Create a custom packet with all the features
        custom_packet = Ether() / IP(src=src, dst=dst) / \
                        Raw(bytes(src, "utf-8") + b"\x00" * (16 - len(src)) + \
                            bytes(dst, "utf-8") + b"\x00" * (16 - len(dst)) + \
                            struct.pack(">I", pktcount) + \
                            struct.pack(">I", bytecount) + \
                            struct.pack(">f", dur) + \
                            struct.pack(">I", dur_nsec) + \
                            struct.pack(">I", pktrate) + \
                            bytes(Protocol, "utf-8") + b"\x00" * (16 - len(Protocol)) + \
                            struct.pack(">H", port_no) + \
                            struct.pack(">I", tx_bytes) + \
                            struct.pack(">I", rx_bytes))
        custom_packets.append(custom_packet)

    # Save the custom packet as a PCAP
    wrpcap(filename, custom_packets)

    print("Custom packet with features saved to " + filename)
