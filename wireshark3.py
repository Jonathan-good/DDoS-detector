from scapy.all import *
import time
import socket
from ddos_engine import predict_datalist

local_ip = "192.168.3.115"
packet_count = 0
byte_count = 0
flows = {}

start_time = time.time()
prev_time = start_time


def get_flow(pkt):
    if pkt.haslayer("TCP"):
        return (('TCP', pkt["IP"].src, pkt["IP"].dst, pkt["TCP"].sport, pkt["TCP"].dport),
                ('TCP', pkt["IP"].dst, pkt["IP"].src, pkt["TCP"].dport, pkt["TCP"].sport))
    elif pkt.haslayer("UDP"):
        return (('UDP', pkt["IP"].src, pkt["IP"].dst, pkt["UDP"].sport, pkt["UDP"].dport),
                ('UDP', pkt["IP"].dst, pkt["IP"].src, pkt["UDP"].dport, pkt["UDP"].sport))
    elif pkt.haslayer("ICMP"):
        return ('ICMP', pkt["IP"].src, pkt["IP"].dst), ('ICMP', pkt["IP"].dst, pkt["IP"].src)
    else:
        return None


def callback(pkt):
    if pkt.haslayer("IP") and (pkt.haslayer("TCP") or pkt.haslayer("UDP") or pkt.haslayer("ICMP")):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        protocol_id = pkt["IP"].proto
        protocol = "TCP" if protocol_id == 6 else "UDP" if protocol_id == 17 \
            else "ICMP" if protocol_id == 1 else "Other"

        src_port = pkt["TCP"].sport if protocol == "TCP" else pkt["UDP"].sport if protocol == "UDP" else 0
        dst_port = pkt["TCP"].dport if protocol == "TCP" else pkt["UDP"].dport if protocol == "UDP" else 0

        port_no = src_port if pkt['IP'].src == local_ip else dst_port

        flow, rev_flow = get_flow(pkt)

        if flow not in flows and rev_flow not in flows:
            flows[flow] = {'start': pkt.time, 'end_time': None, 'pktcount': 0, 'bytecount': 0, 'rx_bytes': 0, 'tx_bytes': 0}
            flows[rev_flow] = {'start': pkt.time, 'end_time': None, 'pktcount': 0, 'bytecount': 0, 'rx_bytes': 0, 'tx_bytes': 0}

        flows[flow]['pktcount'] += 1
        flows[flow]['bytecount'] += len(pkt)
        flows[flow]['end_time'] = time.time()

        flows[rev_flow]['pktcount'] += 1
        flows[rev_flow]['bytecount'] += len(pkt)
        flows[rev_flow]['end_time'] = time.time()

        if pkt['IP'].dst == local_ip:
            flows[flow]['rx_bytes'] += len(pkt)
            flows[rev_flow]['rx_bytes'] += len(pkt)
        else:
            flows[flow]['tx_bytes'] += len(pkt)
            flows[rev_flow]['tx_bytes'] += len(pkt)

        duration = flows[flow]['end_time'] - flows[flow]['start']
        duration_nsec = 1e9 * (flows[flow]['end_time'] - flows[flow]['start']) \
            if flows[flow]['end_time'] is not None else 0

        pktcount = flows[flow]['pktcount']
        bytecount = flows[flow]['bytecount']
        tx_bytes = flows[flow]['tx_bytes']
        rx_bytes = flows[flow]['rx_bytes']

        pkt_rate = pktcount / duration if duration > 0 else 0

        # pktperflow = sum([flows[flow]['pktcount'] for flow in flows]) / len(flows)


        if pkt.haslayer("TCP") and ('F' in str(pkt["TCP"].flags) or 'R' in str(pkt["TCP"].flags)):

            data_dict = {
                "src": src_ip,
                "dst": dst_ip,
                "pktcount": int(pktcount),
                "bytecount": int(bytecount),
                "dur": float(duration),
                "dur_nsec": int(duration_nsec),
                "pktrate": int(pkt_rate),
                "Protocol_ICMP": 1 if protocol == "ICMP" else 0,
                "Protocol_TCP": 1 if protocol == "TCP" else 0,
                "Protocol_UDP": 1 if protocol == "UDP" else 0,
                "port_no": int(port_no),
                "tx_bytes": tx_bytes,
                "rx_bytes": rx_bytes,
            }

            infos, prediction = predict_datalist(data_dict)



            if prediction[0][2] == 'likely a DDOS attack' and flows[flow]['end_time'] is not None:

                if prediction[0][1] == local_ip:
                    print(f"DDOS detected: {prediction[0][0]} to {prediction[0][1]}")
                    print(f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} with flow {flow}")
                    print(f"Transmitted bytes from local: {tx_bytes}, Received bytes to local: {rx_bytes}")
                    print(f"Packet Count: {pktcount}, Byte Count: {bytecount}")
                    print(f"Duration: {duration:.3f}, Duration in Nanoseconds: {duration_nsec:.3f}")
                    print(f"Packet Rate: {pkt_rate:.3f} packets/second")
                    print("\n")


            del flows[flow]
            del flows[rev_flow]



        # print(f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} with flow {flow}")
        # print(f"Transmitted bytes from local: {tx_bytes}, Received bytes to local: {rx_bytes}")
        # print(f"Packet Count: {pktcount}, Byte Count: {bytecount}")
        # print(f"Duration: {duration:.3f}, Duration in Nanoseconds: {duration_nsec:.3f}")
        # print(f"Packet Rate: {pkt_rate:.3f} packets/second")
        # print("\n")

sniff(iface="en0", prn=callback, store=0, filter="(tcp port 8888) or udp or icmp")
