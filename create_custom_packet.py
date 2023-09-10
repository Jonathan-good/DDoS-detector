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
    print("Enter the timestamp: ")
    dt = int(input())

    print("Enter the switch: ")
    switch = int(input())

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

    tot_dur = float((dur + dur_nsec / math.pow(10, 9))*math.pow(10, 9))

    print("Enter the number of flows: ")
    flows = int(input())

    print("Enter the packet ins: ")
    packetins = int(input())

    print("Enter the packet per flow: ")
    pktperflow = int(input())

    print("Enter the byte per flow: ")
    byteperflow = int(input())

    print("Enter the packet rate: ")
    pktrate = int(input())

    print("Enter the pair flow: ")
    Pairflow = int(input())

    print("Enter the protocol(UDP/TCP/ICMP): ")
    Protocol = input()

    print("Enter the port number: ")
    port_no = int(input())

    print("Enter the tx bytes: ")
    tx_bytes = int(input())

    print("Enter the rx bytes: ")
    rx_bytes = int(input())

    print("Enter the tx kbps: ")
    tx_kbps = int(input())

    print("Enter the rx kbps: ")
    rx_kbps = float(input())

    print("Enter the total kbps: ")
    tot_kbps = float(input())

    # Create a custom packet with all the features
    custom_packet = [dt, switch, src, dst, pktcount, bytecount, dur, dur_nsec, tot_dur, flows, packetins,
                     pktperflow, byteperflow, pktrate, Pairflow, Protocol, port_no, tx_bytes, rx_bytes, tx_kbps,
                     rx_kbps, tot_kbps]

    custom_data.append(custom_packet)

custom_data = np.array(custom_data, dtype=object)


if not os.path.exists("custom_packets"):
    os.makedirs("custom_packets")

create_pcap_file(f'custom_packets/{file_name}.pcap', custom_data)
