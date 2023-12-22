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

        if pkt.haslayer("TCP") and ('F' in str(pkt["TCP"].flags) or 'R' in str(pkt["TCP"].flags)):
            termination_reason = "FIN" if 'F' in str(pkt["TCP"].flags) else "RST"
            print(f"TCP Session ended due to {termination_reason} flag: {flow}, {rev_flow}")
            del flows[flow]
            del flows[rev_flow]
        elif prediction[0][2] == 'likely a DDOS attack' and flows[flow]['end_time'] is not None:
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
        # elif prediction[0][2] == 'NOT a DDOS attack' and flows[flow]['end_time'] is not None:
        #     if prediction[0][1] == local_ip:
        #         print(f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} with flow {flow}")
        #         print(f"Transmitted bytes from local: {tx_bytes}, Received bytes to local: {rx_bytes}")
        #         print(f"Packet Count: {pktcount}, Byte Count: {bytecount}")
        #         print(f"Duration: {duration:.3f}, Duration in Nanoseconds: {duration_nsec:.3f}")
        #         print(f"Packet Rate: {pkt_rate:.3f} packets/second")
        #         print("\n")
        #         del flows[flow]
        #         del flows[rev_flow]


        # print(f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} with flow {flow}")
        # print(f"Transmitted bytes from local: {tx_bytes}, Received bytes to local: {rx_bytes}")
        # print(f"Packet Count: {pktcount}, Byte Count: {bytecount}")
        # print(f"Duration: {duration:.3f}, Duration in Nanoseconds: {duration_nsec:.3f}")
        # print(f"Packet Rate: {pkt_rate:.3f} packets/second")
        # print("\n")

sniff(iface="en0", prn=callback, store=0, filter="(tcp port 80 or tcp port 443) or icmp")


# DDOS detected: 140.82.114.22 to 192.168.1.122
# Packet from 140.82.114.22:443 to 192.168.1.122:64459 with flow ('TCP', '140.82.114.22', '192.168.1.122', 443, 64459)
# Transmitted bytes from local: 0, Received bytes to local: 66
# Packet Count: 1, Byte Count: 66
# Duration: 0.339, Duration in Nanoseconds: 338598728.180
# Packet Rate: 2.953 packets/second

# Packet from 144.195.23.105:443 to 192.168.1.122:57147 with flow ('TCP', '144.195.23.105', '192.168.1.122', 443, 57147)
# Transmitted bytes from local: 0, Received bytes to local: 104
# Packet Count: 1, Byte Count: 104
# Duration: 1.023, Duration in Nanoseconds: 1022812128.067
# Packet Rate: 0.978 packets/second