import numpy as np
import math

from ddos_engine import predict
from pcap_generate import create_pcap_file
import os

# Ask user to enter a file name

file_name = input("Enter a file name: ")

number_packets = int(input("Enter the number of packets: "))

custom_data = []

# Ask user to provide the data one by one for the custom packet
for i in range(number_packets):
    print("Enter the data for the custom packet number " + str(i + 1) + ":")

    print("Enter the source IP(x.x.x.x): ")
    src = input()

    print("Enter the destination IP(x.x.x.x): ")
    dst = input()

    print("Enter the packet count: ")
    pktcount = int(input())

    print("Enter the byte count: ")
    bytecount = int(input())

    print("Enter the duration: ")
    dur = float(input())

    print("Enter the duration of nsec: ")
    dur_nsec = int(input())

    print("Enter the packet rate: ")
    pktrate = int(input())

    print("Enter the protocol(UDP/TCP/ICMP): ")
    Protocol = input()

    print("Enter the port number: ")
    port_no = int(input())

    print("Enter the tx bytes: ")
    tx_bytes = int(input())

    print("Enter the rx bytes: ")
    rx_bytes = int(input())

    # Create a custom packet with all the features
    custom_packet = [src, dst, pktcount, bytecount, dur, dur_nsec, pktrate, Protocol, port_no, tx_bytes, rx_bytes]

    custom_data.append(custom_packet)

custom_data = np.array(custom_data, dtype=object)


if not os.path.exists("custom_packets"):
    os.makedirs("custom_packets")

create_pcap_file(f'custom_packets/{file_name}.pcap', custom_data)
