from scapy.all import *
import struct


def create_pcap_file(filename, dataset):
    custom_packets = []

    for data in dataset:
        # Define values for the features
        dt = data[0]
        switch = data[1]
        src = data[2]
        dst = data[3]
        pktcount = data[4]
        bytecount = data[5]
        dur = data[6]
        dur_nsec = data[7]
        tot_dur = data[8]
        flows = data[9]
        packetins = data[10]
        pktperflow = data[11]
        byteperflow = data[12]
        pktrate = data[13]
        Pairflow = data[14]
        Protocol = data[15]
        port_no = data[16]
        tx_bytes = data[17]
        rx_bytes = data[18]
        tx_kbps = data[19]
        rx_kbps = data[20]
        tot_kbps = data[21]

        # Create a custom packet with all the features
        custom_packet = Ether() / IP(src=src, dst=dst) / \
                        Raw(struct.pack(">I", dt) + \
                            struct.pack(">I", switch) + \
                            bytes(src, "utf-8") + b"\x00" * (16 - len(src)) + \
                            bytes(dst, "utf-8") + b"\x00" * (16 - len(dst)) + \
                            struct.pack(">I", pktcount) + \
                            struct.pack(">I", bytecount) + \
                            struct.pack(">f", dur) + \
                            struct.pack(">I", dur_nsec) + \
                            struct.pack(">f", tot_dur) + \
                            struct.pack(">I", flows) + \
                            struct.pack(">I", packetins) + \
                            struct.pack(">I", pktperflow) + \
                            struct.pack(">I", byteperflow) + \
                            struct.pack(">I", pktrate) + \
                            struct.pack(">I", Pairflow) + \
                            bytes(Protocol, "utf-8") + b"\x00" * (16 - len(Protocol)) + \
                            struct.pack(">H", port_no) + \
                            struct.pack(">I", tx_bytes) + \
                            struct.pack(">I", rx_bytes) + \
                            struct.pack(">I", tx_kbps) + \
                            struct.pack(">f", rx_kbps) + \
                            struct.pack(">f", tot_kbps))
        custom_packets.append(custom_packet)

    # Save the custom packet as a PCAP
    wrpcap(filename, custom_packets)

    print("Custom packet with features saved to " + filename)
