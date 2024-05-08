import argparse
import os
import pickle
import random
import sys
import socket
import time
from multiprocessing import Manager, Process

from sklearn.feature_extraction.text import CountVectorizer
import hashlib
import pyshark

from util_functions import *  # Ensure you have this module to handle utility functions

IDS2018_DDOS_FLOWS = {
    'attackers': ['18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135', '18.219.5.43',
                  '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42'],
    'victims': ['18.218.83.150', '172.31.69.28']}

IDS2017_DDOS_FLOWS = {'attackers': ['172.16.0.1'],
                      'victims': ['192.168.10.50']}

CUSTOM_DDOS_SYN = {'attackers': ['11.0.0.' + str(x) for x in range(1, 255)],
                   'victims': ['10.42.0.2']}

DOS2019_FLOWS = {'attackers': ['172.16.0.5'], 'victims': ['192.168.50.1', '192.168.50.4']}

DDOS_ATTACK_SPECS = {
    'DOS2017': IDS2017_DDOS_FLOWS,
    'DOS2018': IDS2018_DDOS_FLOWS,
    'SYN2020': CUSTOM_DDOS_SYN,
    'DOS2019': DOS2019_FLOWS
}

SEED = 42  # Example seed, adjust as necessary
MAX_FLOW_LEN = 100  # Adjust as needed
TIME_WINDOW = 60  # Adjust as needed
TRAIN_SIZE = 0.8  # Adjust as needed

# Initialize global variables if necessary
random.seed(SEED)
np.random.seed(SEED)
vector_proto = CountVectorizer()

vector_proto.fit_transform(protocols)


# Ensure you fit_transform the vector_proto with the necessary data

class PacketFeatures:
    """
    A class to hold the packet features including a forward and backward identifier,
    along with a list of features extracted from each packet.
    """

    def __init__(self):
        """
        (src_ip_addr, src_port, dst_ip_addr, dst_port, protocol)
        """

        self.id_fwd = (0, 0, 0, 0, 0)
        self.id_bwd = (0, 0, 0, 0, 0)
        self.features_list = []

    def __str__(self):
        return "{} -> {}".format(self.id_fwd, self.features_list)


# Function Definitions

def parse_labels(dataset_type=None, attackers=None, victims=None, label=1):
    """
Build the labels based on the dataset type, attackers, and victims.

Parameters:
    dataset_type (str): Specifies the dataset type to use predefined IP addresses.
    attackers (list): Optionally specify a list of attacker IPs (ignored if dataset_type is provided).
    victims (list): Optionally specify a list of victim IPs (ignored if dataset_type is provided).
    label (int): The label to assign to flows between attackers and victims (default is 1 for malicious).

Returns:
    dict: A dictionary where keys are tuples of (attacker IP, victim IP) and values are the assigned labels.
"""

    # Initialize a dictionary to store labels for IP pairs

    ip_pairs = {}

    # Check if a dataset_type is provided and if it exists within predefined specifications

    if dataset_type is not None and dataset_type in DDOS_ATTACK_SPECS:

        data = DDOS_ATTACK_SPECS[dataset_type]

    else:
        return None

    # If dataset_type is valid, use its attackers and victims list
    # If dataset_type is not provided or invalid, return None
    # Loop through each attacker IP address
    # Loop through each victim IP address for the current attacker
    # Construct a key for forward direction (attacker to victim)
    # Construct a key for backward direction (victim to attacker)
    # Assign label to the forward key if not already assigned
    # Assign label to the backward key if not already assigned

    for attacker in data['attackers']:
        for victim in data['victims']:
            ip_src = attacker
            ip_dst = victim
            ip_pairs[(ip_src, ip_dst)] = label
            ip_pairs[(ip_dst, ip_src)] = label

    # Return the dictionary containing the labels for IP pairs

    return ip_pairs


def parse_packet(pkt):
    """
    Parse individual packets to extract features and identifiers.

    Parameters:
        pkt (pyshark.packet.packet.Packet): The packet to parse.

    Returns:
        packet_features: An object containing the parsed packet features, or None if the packet is not suitable.
    """

    # Initialize a packet_features object

    packet_features = PacketFeatures()
    packet_id_fwd = [0, 0, 0, 0, 0]

    # Try to extract packet features within a try block to handle exceptions

    try:
        packet_features.features_list.append(float(pkt.sniff_timestamp))
        packet_features.features_list.append(int(pkt.length))
        packet_features.features_list.append(
            int(hashlib.sha256(str(pkt.highest_layer).encode('utf-8')).hexdigest(), 16) % 10 ** 8)
        packet_features.features_list.append(int(pkt.ip.flags, 16))

        packet_id_fwd[0] = pkt.ip.src
        packet_id_fwd[2] = pkt.ip.dst

        protocol_list = vector_proto.transform([pkt.frame_info.protocols]).toarray().tolist()[0]

        # This line modifies the protocols list by converting it into a binary representation. It iterates over each
        # element in the protocols list and replaces it with 1 if the element is greater than or equal to 1, indicating
        # the presence of that protocol in the packet, and 0 otherwise. This step seems to be aimed at ensuring that
        # each protocol is only counted once, as sometimes they might appear multiple times in the
        # pkt.frame_info.protocols list.

        protocol_list = [1 if x >= 1 else 0 for x in protocol_list]

        protocols_value = int(np.dot(np.array(protocol_list), powers_of_two))

        packet_features.features_list.append(protocols_value)

        protocol = int(pkt.ip.proto)

        packet_id_fwd[4] = protocol

        if pkt.transport_layer is not None:
            if protocol == socket.IPPROTO_TCP:
                packet_features.features_list.append(int(pkt.tcp.len))
                packet_features.features_list.append(int(pkt.tcp.ack))
                packet_features.features_list.append(int(pkt.tcp.flags, 16))
                packet_features.features_list.append(int(pkt.tcp.window_size_value))

                packet_id_fwd[1] = int(pkt.tcp.srcport)
                packet_id_fwd[3] = int(pkt.tcp.dstport)
                packet_features.features_list = packet_features.features_list + [0, 0]

            elif protocol == socket.IPPROTO_UDP:
                packet_features.features_list = packet_features.features_list + [0, 0, 0, 0]
                packet_features.features_list.append(int(pkt.udp.length))
                packet_features.features_list = packet_features.features_list + [0]

                packet_id_fwd[1] = int(pkt.udp.srcport)
                packet_id_fwd[3] = int(pkt.udp.dstport)

        elif protocol == socket.IPPROTO_ICMP:
            packet_features.features_list = packet_features.features_list + [0, 0, 0, 0, 0]
            packet_features.features_list.append(int(pkt.icmp.type))

            packet_id_fwd[1] = 0
            packet_id_fwd[3] = 0

        else:
            packet_features.features_list = packet_features.features_list + [0, 0, 0, 0, 0, 0]
            packet_id_fwd[1] = 0
            packet_id_fwd[3] = 0
            packet_id_fwd[4] = 0

        packet_features.id_fwd = tuple(packet_id_fwd)

        packet_id_bwd = packet_id_fwd.copy()
        packet_id_bwd[0], packet_id_bwd[2] = packet_id_bwd[2], packet_id_bwd[0]
        packet_id_bwd[1], packet_id_bwd[3] = packet_id_bwd[3], packet_id_bwd[1]
        packet_features.id_bwd = tuple(packet_id_bwd)

        return packet_features

    except AttributeError as e:
        print(e)
        return None

    # Extract and append packet timestamp to the features list
    # Extract packet length and append to the features list
    # Hash the highest layer of the packet, convert to integer, and append to the features list
    # Extract IP flags, convert to integer, and append to the features list
    # Extract source and destination IP addresses and store in a temporary list
    # Transform protocols using a vectorizer and calculate their value, then append to the features list
    # Extract transport layer protocol and port information, append to the features list
    # Check if packet is TCP and extract TCP-specific features, append to the features list
    # Else if packet is UDP, extract UDP-specific features and append to the features list
    # Else if packet is ICMP, extract ICMP type and append to the features list
    # For packets not TCP/UDP/ICMP, pad the features list as necessary
    # Set the forward and backward identifiers for the packet_features object
    # Return the packet_features object with extracted data
    # Catch and handle AttributeError exceptions, returning None for packets that don't meet criteria


def process_pcap(pcap_file, in_labels=0, max_flow_len=0, labelled_flows=[], max_flows=0, traffic_type='all',
                 time_window=TIME_WINDOW):
    """
    Offline preprocessing of pcap files for model training, validation, and testing.

    Parameters:
        pcap_file (str): Path to the pcap file.
        in_labels (dict): Dictionary of labels for IP pairs.
        max_flow_len (int): Maximum length of a flow to consider.
        labelled_flows (list): A list to store labelled flow data.
        max_flows (int, optional): Maximum number of flows to process.
        traffic_type (str, optional): Type of traffic to process ('all', 'ddos', or 'benign').
        time_window (float, optional): Length of the time window for packet grouping.

    Returns:
        None: This function modifies the labelled_flows list in place.
    """

    # data = pyshark.FileCapture(pcap_file)
    #
    # features = []
    #
    # # for pkt in data:
    # #     features.append(parse_packet(pkt))
    #
    # print(parse_packet(data[0]))

    # Record the start time of the function for performance measurement

    measurement_start = time.time()

    # Initialize a temporary dictionary to store packet flows

    ordered_dict = OrderedDict()

    # Set the initial start time window for time-based flow grouping

    start_time_window = -1

    # Extract the pcap file name from the given file path

    pcap_file_name = pcap_file.split('/')[-1]

    # Print a message indicating the start of pcap file processing

    print(f"Processing pcap file: {pcap_file_name}")

    # Open the pcap file using pyshark for packet analysis

    pcap = pyshark.FileCapture(pcap_file)

    # Iterate over each packet in the pcap file

    for i, pkt in enumerate(pcap):

        # Print progress for every 1000 packets processed

        if i % 1000 == 0:
            print(f"Packets processed: {i}")

        # Update the time window start time based on packet timestamps

        if start_time_window == -1 or float(pkt.sniff_timestamp) > start_time_window + time_window:
            start_time_window = float(pkt.sniff_timestamp)

        # Parse the current packet and extract its features

        pf = parse_packet(pkt)

        # Store the parsed packet in the temporary dictionary

        ordered_dict = store_packet(pf, ordered_dict, start_time_window, max_flow_len)

        # Break the loop if the maximum number of flows is reached

        if max_flows > 0 and len(ordered_dict) >= max_flows:
            break

    # Apply labels to the processed flows based on input criteria

    apply_labels(ordered_dict, labelled_flows, in_labels, traffic_type)

    # Print progress for every 1000 packets processed
    # Update the time window start time based on packet timestamps
    # Parse the current packet and extract its features
    # Store the parsed packet in the temporary dictionary
    # Break the loop if the maximum number of flows is reached
    # Apply labels to the processed flows based on input criteria
    # Print a completion message with the processing duration

    print(f"Completed processing pcap file: {pcap_file_name}")

    # Close the pcap file after processing

    pcap.close()


def process_live_traffic(cap, in_labels, max_flow_len, traffic_type='all', time_window=TIME_WINDOW):
    """
Transforms live traffic into input samples for inference.

Parameters:
    cap (pyshark.LiveCapture or pyshark.FileCapture): Capture object for live or offline packet capture.
    in_labels (dict): Dictionary of labels for IP pairs.
    max_flow_len (int): Maximum length of a flow to consider.
    traffic_type (str, optional): Type of traffic to process ('all', 'ddos', or 'benign').
    time_window (float, optional): Length of the time window for packet grouping.

Returns:
    list: A list of labelled flows extracted from the live traffic.
"""

    # Record the start time for processing live traffic

    measurement_start = time.time()

    # Initialize an ordered dictionary for storing live traffic flows

    ordered_dict = OrderedDict()

    # Initialize a list for labelled flows

    labelled_flows = []

    # Set the initial start time and end time for the live capture window

    initial_time = measurement_start
    end_time = measurement_start + time_window

    # Check if the capture object is a live capture instance

    if isinstance(cap, pyshark.LiveCapture):
        for pkt in cap.sniff_continuously():
            if float(pkt.sniff_timestamp) > end_time:
                break

            pf = parse_packet(pkt)

            ordered_dict = store_packet(pf, ordered_dict, initial_time, max_flow_len)

    elif isinstance(cap, pyshark.FileCapture):
        while time.time() < time_window:
            pkt = cap.next()
            pf = parse_packet(pkt)

            ordered_dict = store_packet(pf, ordered_dict, initial_time, max_flow_len)

    # Capture packets continuously until the time window expires
    # Parse each packet and update the temporary dictionary with live traffic flows
    # For file captures, process packets until the end of the file or the time window is reached
    # Parse each packet and update the temporary dictionary
    # Apply labels to the processed live traffic flows

    apply_labels(ordered_dict, labelled_flows, in_labels, traffic_type)

    # Return the list of labelled flows

    return labelled_flows


def store_packet(pf, temp_dict, start_time_window, max_flow_len):
    """
Store packet information in the packet flow dictionary.

Parameters:
    pf (packet_features): Object containing features extracted from the packet.
    temp_dict (dict): Dictionary to store packet flows.
    start_time_window (float): Start time of the time window for grouping packets.
    max_flow_len (int): Maximum length of a flow.

Returns:
    dict: Updated packet flow dictionary.
"""

    # Check if the packet features object is not None

    if pf is not None:
        if pf.id_fwd in temp_dict and start_time_window in temp_dict[pf.id_fwd] and \
                temp_dict[pf.id_fwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[pf.id_fwd][start_time_window] = np.vstack(
                [temp_dict[pf.id_fwd][start_time_window], pf.features_list])
        elif pf.id_bwd in temp_dict and start_time_window in temp_dict[pf.id_bwd] and \
                temp_dict[pf.id_bwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[pf.id_bwd][start_time_window] = np.vstack(
                [temp_dict[pf.id_bwd][start_time_window], pf.features_list])
        else:
            if pf.id_fwd not in temp_dict and pf.id_bwd not in temp_dict:
                temp_dict[pf.id_fwd] = {start_time_window: np.array([pf.features_list]), "label": 0}
            elif pf.id_fwd in temp_dict and start_time_window in temp_dict[pf.id_fwd]:
                temp_dict[pf.id_fwd] = {start_time_window: np.array([pf.features_list])}
            elif pf.id_bwd in temp_dict and start_time_window in temp_dict[pf.id_bwd]:
                temp_dict[pf.id_bwd] = {start_time_window: np.array([pf.features_list])}

    # If forward flow ID exists in the dictionary and within the time window and flow length limit
    # Append the packet to the existing forward flow
    # Else if backward flow ID exists and within constraints
    # Append the packet to the existing backward flow
    # Else, check for new flow initialization conditions
    # Initialize a new flow for the packet in the dictionary
    # Return the updated dictionary with the packet information stored

    return temp_dict


def apply_labels(flows, labelled_flows, labels, traffic_type):
    """
    Apply labels to flows based on labelled flows and traffic type.

    Parameters:
        flows (dict): Dictionary containing flows.
        labelled_flows (list): List of labelled flows.
        labels (dict): Dictionary containing labels.
        traffic_type (str): Type of traffic ('ddos' or 'benign').

    Returns:
        None: This function modifies the labelled_flows list in place.
    """

    # Iterate over each flow in the input flows dictionary

    j = 0

    for pkt_info, flow in flows.items():

        if labels is not None:
            ip = (pkt_info[0], pkt_info[2])

            flow["label"] = labels.get(ip, 0)

        for time_window, fl in flow.items():
            amin = np.amin(fl, axis=0)
            if not np.isscalar(amin):
                amin = amin[0]

            fl[:, 0] = fl[:, 0] - amin

        if traffic_type == 'ddos' and flow["label"] == 0:
            continue
        elif traffic_type == 'benign' and flow["label"] == 0:
            continue
        else:
            labelled_flows.append((pkt_info, flow))

    # If labels are provided, assign labels to flows based on IP pairs

    # Adjust packet timestamps within each flow to be relative to the flow start
    # Filter flows to include based on the specified traffic type (DDoS or benign)
    # Add qualified flows to the list of labelled flows


def count_flows(preprocessed_flows):
    """
Returns the total number of flows, differentiating between benign and malicious.

Parameters:
    preprocessed_flows (list): List of preprocessed flow data.

Returns:
    tuple: A tuple containing counts of total flows, ddos flows, benign flows, total fragments, ddos fragments, and benign fragments.
"""

    # Initialize counters for total, DDoS, and benign flows

    total_flows = len(preprocessed_flows)
    ddos_flows = 0
    ddos_fragments = 0
    total_fragments = 0

    # Iterate through each preprocessed flow

    for flow in preprocessed_flows:
        flow_fragments = len(flow[1])
        total_fragments += flow_fragments
        if flow[1]["label"] == 1:
            ddos_flows += 1
            ddos_fragments += flow_fragments

    # Count the number of flows and categorize them as DDoS or benign based on labels
    # Return a summary of flow counts and categories

    return (total_flows, ddos_flows, total_flows - ddos_flows), (
        total_fragments, ddos_fragments, total_fragments - ddos_fragments)


def balance_dataset(flows, total_fragments=float('inf')):
    """
Balance the dataset based on the number of benign and malicious fragments of flows.

Parameters:
    flows (list): List of preprocessed flow data.
    total_fragments (float, optional): Desired total number of fragments in the balanced dataset.

Returns:
    list: A new list of flows balanced according to the specified criteria.
"""

    # Determine the minimum number of fragments needed to balance the dataset
    # Randomly shuffle the list of flows
    # Iterate over each flow and select a balanced number of benign and DDoS flows
    # Return the balanced list of flows and the counts of benign and DDoS fragments

    flow_list = []
    _, (_, ddos_fragment_count, benign_fragment_count) = count_flows(flows)

    random.shuffle(flows)

    for flow in flows:
        if flow[1]["label"] == 1:
            if ddos_fragment_count > benign_fragment_count:
                flow_list.append(flow)
                ddos_fragment_count -= 1
        else:
            if benign_fragment_count > ddos_fragment_count:
                flow_list.append(flow)
                benign_fragment_count -= 1

        if ddos_fragment_count == 0 and benign_fragment_count == 0:
            break

    return flow_list


def dataset_to_list_of_fragments(dataset):
    """
    Convert the dataset from dictionaries with 5-tuples keys into a list of flow fragments and another list of labels.

    Parameters:
        dataset (dict): The dataset to convert, comprised of flow data.

    Returns:
        tuple: Two lists, the first containing flow fragments and the second containing corresponding labels.
    """

    # Initialize lists for storing fragments and their corresponding labels

    flow_fragments = []
    labels = []
    keys = []

    # Iterate through each flow in the dataset

    for tup, flow in dataset.items():
        for key, fragments in flow.items():
            if key != "label":
                flow_fragments.append(fragments)
                labels.append(flow["label"])
                keys.append(key)

    # Extract and store each flow fragment and its label in the lists
    # Return the lists of flow fragments and labels

    return flow_fragments, labels, keys


def train_test_split(flow_list, train_size=TRAIN_SIZE, shuffle=True):
    """
    Split the dataset into training and testing sets.

    Parameters:
        flow_list (list): The list of flows to split.
        train_size (float): The proportion of the dataset to include in the train split.
        shuffle (bool): Whether to shuffle the data before splitting.

    Returns:
        tuple: Two lists, the first is the training set and the second is the testing set.
    """

    test = []
    _, (total_examples, _, _) = count_flows(flow_list)

    # Determine the number of examples to allocate to the test set based on the split ratio

    train_count = int(total_examples * train_size)

    # Shuffle the flow list if shuffling is enabled

    if shuffle:
        random.shuffle(flow_list)

    # Separate a portion of the dataset into the test list until the test size requirement is met

    X_train = flow_list[:train_count]
    X_test = flow_list[train_count:]

    # Return the remaining flows as the training set and the separated flows as the test set

    return X_train, X_test


def main(argv):
    """
    Main function to parse arguments and call respective processing functions.
    Input: Command-line arguments (argv) provided by the user when running the script
    Output: Depending on the command, could be a preprocessed dataset, live traffic analysis, or model training evaluation

    """
    # Parse command-line arguments using argparse or a similar library

    # Define expected arguments such as dataset folder, output folder, preprocessing options, etc.

    # Check if dataset processing is requested
    # Validate necessary arguments like dataset folder and type are provided
    # Process each pcap file in the dataset folder
    # For each file, parse packets, extract features, and store in a structured format
    # Optionally balance the dataset based on the command-line arguments
    # Save the processed dataset to the specified output location

    # Check if live traffic processing is requested
    # Validate necessary arguments like capture interface or pcap file for live traffic are provided
    # Capture live traffic and process it similar to dataset processing
    # Parse live packets, extract features, and apply labels based on predefined criteria
    # Store processed live traffic data for further analysis or real-time detection

    # Check if dataset balancing is requested
    # Load preprocessed datasets
    # Balance the dataset by ensuring an equal number of samples from each class
    # Save the balanced dataset to the specified output location

    # Handle other command-line operations such as training models, evaluating performance, etc.
    # Based on command-line arguments, perform requested operations such as model training or evaluation
    # Ensure necessary parameters for these operations are validated and used correctly

    # Provide help and usage information if invalid arguments are provided or on request
    # Display help information that describes each command-line option
    # Offer examples of command usage for clarity

    # Entry point to verify if the script is being run directly
    # Call the main function with sys.argv to process command-line arguments

    command_options = " ".join(str(x) for x in argv[1:])

    help_string = 'Usage[0]: python3 dataset_parser_v2.py --dataset_type <dataset_name> --dataset_folder <folder path> --dataset_id <dataset identifier> --packets_per_flow <n> --time_window <t>\n' \
                  'Usage[1]: python3 dataset_parser_v2.py --preprocess_folder <folder path>'
    manager = Manager()

    parser = argparse.ArgumentParser(
        description='Dataset parser',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--dataset_folder', nargs='+', type=str,
                        help='Folder with the dataset')
    parser.add_argument('-o', '--output_folder', nargs='+', type=str,
                        help='Output folder')
    parser.add_argument('-f', '--traffic_type', default='all', nargs='+', type=str,
                        help='Type of flow to process (all, benign, ddos)')
    parser.add_argument('-p', '--preprocess_folder', nargs='+', type=str,
                        help='Folder with preprocessed data')
    parser.add_argument('--preprocess_file', nargs='+', type=str,
                        help='File with preprocessed data')
    parser.add_argument('-b', '--balance_folder', nargs='+', type=str,
                        help='Folder where balancing datasets')
    parser.add_argument('-n', '--packets_per_flow', nargs='+', type=str,
                        help='Packet per flow sample')
    parser.add_argument('-s', '--samples', default=float('inf'), type=int,
                        help='Number of training samples in the reduced output')
    parser.add_argument('-i', '--dataset_id', nargs='+', type=str,
                        help='String to append to the names of output files', default=[""])
    parser.add_argument('-m', '--max_flows', default=0, type=int,
                        help='Max number of flows to extract from the pcap files')
    parser.add_argument('-l', '--label', default=1, type=int,
                        help='Label assigned to the DDoS class')

    parser.add_argument('-t', '--dataset_type', nargs='+', type=str,
                        help='Type of the dataset. Available options are: DOS2017, DOS2018, DOS2019, SYN2020')

    parser.add_argument('-w', '--time_window', nargs='+', type=str,
                        help='Length of the time window')

    parser.add_argument('--no_split', help='Do not split the dataset', action='store_true')

    args = parser.parse_args()

    if args.packets_per_flow is not None:
        max_flow_len = int(args.packets_per_flow[0])
    else:
        max_flow_len = MAX_FLOW_LEN

    if args.time_window is not None:
        time_window = float(args.time_window[0])
    else:
        time_window = TIME_WINDOW

    if args.dataset_id is not None:
        dataset_id = str(args.dataset_id[0])
    else:
        dataset_id = ''

    if args.traffic_type is not None:
        traffic_type = str(args.traffic_type[0])
    else:
        traffic_type = 'all'

    if args.dataset_folder is not None and args.dataset_type is not None:
        process_list = []
        flows_list = []

        if args.output_folder is not None and os.path.isdir(args.output_folder[0]) is True:
            output_folder = args.output_folder[0]
        else:
            output_folder = args.dataset_folder[0]

        filelist = glob.glob(args.dataset_folder[0] + '/*.pcap')
        in_labels = parse_labels(args.dataset_type[0], args.dataset_folder[0], label=args.label)

        start_time = time.time()
        for file in filelist:
            try:
                flows = manager.list()
                p = Process(target=process_pcap, args=(
                    file, in_labels, max_flow_len, flows, args.max_flows, traffic_type,
                    time_window))
                process_list.append(p)
                flows_list.append(flows)
            except FileNotFoundError as e:
                continue

        for p in process_list:
            p.start()

        for p in process_list:
            p.join()

        np.seterr(divide='ignore', invalid='ignore')
        try:
            preprocessed_flows = list(flows_list[0])
        except:
            print("ERROR: No traffic flows. \nPlease check that the dataset folder name (" + args.dataset_folder[
                0] + ") is correct and \nthe folder contains the traffic traces in pcap format (the pcap extension is mandatory)")
            exit(1)

        # concatenation of the features
        for results in flows_list[1:]:
            preprocessed_flows = preprocessed_flows + list(results)

        process_time = time.time() - start_time

        if dataset_id == '':
            dataset_id = str(args.dataset_type[0])

        filename = str(int(time_window)) + 't-' + str(max_flow_len) + 'n-' + dataset_id + '-preprocess'
        output_file = output_folder + '/' + filename
        output_file = output_file.replace("//", "/")  # remove double slashes when needed

        with open(output_file + '.data', 'wb') as filehandle:
            # store the data as binary data stream
            pickle.dump(preprocessed_flows, filehandle)

        (total_flows, ddos_flows, benign_flows), (total_fragments, ddos_fragments, benign_fragments) = count_flows(
            preprocessed_flows)

        log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | dataset_type:" + args.dataset_type[0] + \
                     " | flows (tot,ben,ddos):(" + str(total_flows) + "," + str(benign_flows) + "," + str(ddos_flows) + \
                     ") | fragments (tot,ben,ddos):(" + str(total_fragments) + "," + str(benign_fragments) + "," + str(
            ddos_fragments) + \
                     ") | options:" + command_options + " | process_time:" + str(process_time) + " |\n"
        print(log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)

    if args.preprocess_folder is None and args.preprocess_file is None:
        args.preprocess_folder[0] = args.dataset_folder[0]

    if args.balance_folder is None:
        args.balance_folder[0] = args.dataset_folder[0]

    if args.preprocess_folder is not None or args.preprocess_file is not None:
        if args.preprocess_folder is not None:
            output_folder = args.output_folder[0] if args.output_folder is not None else args.preprocess_folder[0]
            filelist = glob.glob(args.preprocess_folder[0] + '/*.data')
        else:
            output_folder = args.output_folder[0] if args.output_folder is not None else os.path.dirname(
                os.path.realpath(args.preprocess_file[0]))
            filelist = args.preprocess_file
        print(filelist)
        # obtain time_window and flow_len from filename and ensure that all files have the same values
        time_window = None
        max_flow_len = None
        dataset_id = None
        for file in filelist:
            filename = file.split('/')[-1].strip()
            filename = filename.split('\\')[-1].strip()
            print(filename.split('-')[0].strip().replace('t', ''))
            current_time_window = int(filename.split('-')[0].strip().replace('t', ''))
            current_max_flow_len = int(filename.split('-')[1].strip().replace('n', ''))
            current_dataset_id = str(filename.split('-')[2].strip())
            if time_window != None and current_time_window != time_window:
                print("Incosistent time windows!!")
                exit()
            else:
                time_window = current_time_window
            if max_flow_len != None and current_max_flow_len != max_flow_len:
                print("Incosistent flow lengths!!")
                exit()
            else:
                max_flow_len = current_max_flow_len

            if dataset_id != None and current_dataset_id != dataset_id:
                dataset_id = "IDS201X"
            else:
                dataset_id = current_dataset_id

        preprocessed_flows = []
        for file in filelist:
            with open(file, 'rb') as filehandle:
                # read the data as binary data stream
                preprocessed_flows = preprocessed_flows + pickle.load(filehandle)

        # balance samples and redux the number of samples when requested
        preprocessed_flows, benign_fragments, ddos_fragments = balance_dataset(preprocessed_flows, args.samples)

        if len(preprocessed_flows) == 0:
            print("Empty dataset!")
            exit()

        preprocessed_train, preprocessed_test = train_test_split(preprocessed_flows, train_size=TRAIN_SIZE,
                                                                 shuffle=True)
        preprocessed_train, preprocessed_val = train_test_split(preprocessed_train, train_size=TRAIN_SIZE, shuffle=True)

        X_train, y_train, _ = dataset_to_list_of_fragments(preprocessed_train)
        X_val, y_val, _ = dataset_to_list_of_fragments(preprocessed_val)
        X_test, y_test, _ = dataset_to_list_of_fragments(preprocessed_test)

        # normalization and padding
        X_full = X_train + X_val + X_test
        y_full = y_train + y_val + y_test
        mins, maxs = static_min_max(time_window=time_window)

        total_examples = len(y_full)
        total_ddos_examples = np.count_nonzero(y_full)
        total_benign_examples = total_examples - total_ddos_examples

        output_file = output_folder + '/' + str(time_window) + 't-' + str(max_flow_len) + 'n-' + dataset_id + '-dataset'
        if args.no_split == True:  # don't split the dataset
            norm_X_full = normalize_and_padding(X_full, mins, maxs, max_flow_len)
            # norm_X_full = padding(X_full,max_flow_len) # only padding
            norm_X_full_np = np.array(norm_X_full)
            y_full_np = np.array(y_full)

            hf = h5py.File(output_file + '-full.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_full_np)
            hf.create_dataset('set_y', data=y_full_np)
            hf.close()

            [full_packets] = count_packets_in_dataset([norm_X_full_np])
            log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | Total examples (tot,ben,ddos):(" + str(
                total_examples) + "," + str(total_benign_examples) + "," + str(total_ddos_examples) + \
                         ") | Total packets:(" + str(full_packets) + \
                         ") | options:" + command_options + " |\n"
        else:
            norm_X_train = normalize_and_padding(X_train, mins, maxs, max_flow_len)
            norm_X_val = normalize_and_padding(X_val, mins, maxs, max_flow_len)
            norm_X_test = normalize_and_padding(X_test, mins, maxs, max_flow_len)

            norm_X_train_np = np.array(norm_X_train)
            y_train_np = np.array(y_train)
            norm_X_val_np = np.array(norm_X_val)
            y_val_np = np.array(y_val)
            norm_X_test_np = np.array(norm_X_test)
            y_test_np = np.array(y_test)

            hf = h5py.File(output_file + '-train.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_train_np)
            hf.create_dataset('set_y', data=y_train_np)
            hf.close()

            hf = h5py.File(output_file + '-val.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_val_np)
            hf.create_dataset('set_y', data=y_val_np)
            hf.close()

            hf = h5py.File(output_file + '-test.hdf5', 'w')
            hf.create_dataset('set_x', data=norm_X_test_np)
            hf.create_dataset('set_y', data=y_test_np)
            hf.close()

            [train_packets, val_packets, test_packets] = count_packets_in_dataset(
                [norm_X_train_np, norm_X_val_np, norm_X_test_np])
            log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | examples (tot,ben,ddos):(" + str(
                total_examples) + "," + str(total_benign_examples) + "," + str(total_ddos_examples) + \
                         ") | Train/Val/Test sizes: (" + str(norm_X_train_np.shape[0]) + "," + str(
                norm_X_val_np.shape[0]) + "," + str(norm_X_test_np.shape[0]) + \
                         ") | Packets (train,val,test):(" + str(train_packets) + "," + str(val_packets) + "," + str(
                test_packets) + \
                         ") | options:" + command_options + " |\n"

        print(log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)

    if args.balance_folder is not None and args.output_folder is not None:
        output_folder = args.output_folder[0] if args.output_folder is not None else args.balance_folder[0]
        datasets = []
        for folder in args.balance_folder:
            datasets += glob.glob(folder + '/*.hdf5')
        train_filelist = {}
        val_filelist = {}
        test_filelist = {}
        min_samples_train = float('inf')
        min_samples_val = float('inf')
        min_samples_test = float('inf')

        output_filename_prefix = None

        for file in datasets:
            filename = file.split('/')[-1].strip()
            dataset = h5py.File(file, "r")
            X = np.array(dataset["set_x"][:])  # features
            Y = np.array(dataset["set_y"][:])  # labels
            if 'train' in filename:
                key = filename.split('dataset')[0].strip() + 'dataset-balanced-train.hdf5'
                if output_filename_prefix == None:
                    output_filename_prefix = filename.split('IDS')[0].strip()
                else:
                    if filename.split('IDS')[0].strip() != output_filename_prefix:
                        print("Inconsistent datasets!")
                        exit()
                train_filelist[key] = (X, Y)
                if X.shape[0] < min_samples_train:
                    min_samples_train = X.shape[0]
            elif 'val' in filename:
                key = filename.split('dataset')[0].strip() + 'dataset-balanced-val.hdf5'
                if output_filename_prefix == None:
                    output_filename_prefix = filename.split('IDS')[0].strip()
                else:
                    if filename.split('IDS')[0].strip() != output_filename_prefix:
                        print("Inconsistent datasets!")
                        exit()
                val_filelist[key] = (X, Y)
                if X.shape[0] < min_samples_val:
                    min_samples_val = X.shape[0]
            elif 'test' in filename:
                key = filename.split('dataset')[0].strip() + 'dataset-balanced-test.hdf5'
                if output_filename_prefix == None:
                    output_filename_prefix = filename.split('IDS')[0].strip()
                else:
                    if filename.split('IDS')[0].strip() != output_filename_prefix:
                        print("Inconsistent datasets!")
                        exit()
                test_filelist[key] = (X, Y)
                if X.shape[0] < min_samples_test:
                    min_samples_test = X.shape[0]

        final_X = {'train': None, 'val': None, 'test': None}
        final_y = {'train': None, 'val': None, 'test': None}

        for key, value in train_filelist.items():
            X_short = value[0][:min_samples_train, ...]
            y_short = value[1][:min_samples_train, ...]

            if final_X['train'] is None:
                final_X['train'] = X_short
                final_y['train'] = y_short
            else:
                final_X['train'] = np.vstack((final_X['train'], X_short))
                final_y['train'] = np.hstack((final_y['train'], y_short))

        for key, value in val_filelist.items():
            X_short = value[0][:min_samples_val, ...]
            y_short = value[1][:min_samples_val, ...]

            if final_X['val'] is None:
                final_X['val'] = X_short
                final_y['val'] = y_short
            else:
                final_X['val'] = np.vstack((final_X['val'], X_short))
                final_y['val'] = np.hstack((final_y['val'], y_short))

        for key, value in test_filelist.items():
            X_short = value[0][:min_samples_test, ...]
            y_short = value[1][:min_samples_test, ...]

            if final_X['test'] is None:
                final_X['test'] = X_short
                final_y['test'] = y_short
            else:
                final_X['test'] = np.vstack((final_X['test'], X_short))
                final_y['test'] = np.hstack((final_y['test'], y_short))

        for key, value in final_X.items():
            filename = output_filename_prefix + 'IDS201X-dataset-balanced-' + key + '.hdf5'
            hf = h5py.File(output_folder + '/' + filename, 'w')
            hf.create_dataset('set_x', data=value)
            hf.create_dataset('set_y', data=final_y[key])
            hf.close()

        total_flows = final_y['train'].shape[0] + final_y['val'].shape[0] + final_y['test'].shape[0]
        ddos_flows = np.count_nonzero(final_y['train']) + np.count_nonzero(final_y['val']) + np.count_nonzero(
            final_y['test'])
        benign_flows = total_flows - ddos_flows
        [train_packets, val_packets, test_packets] = count_packets_in_dataset(
            [final_X['train'], final_X['val'], final_X['test']])
        log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | total_flows (tot,ben,ddos):(" + str(
            total_flows) + "," + str(benign_flows) + "," + str(ddos_flows) + \
                     ") | Packets (train,val,test):(" + str(train_packets) + "," + str(val_packets) + "," + str(
            test_packets) + \
                     ") | Train/Val/Test sizes: (" + str(final_y['train'].shape[0]) + "," + str(
            final_y['val'].shape[0]) + "," + str(final_y['test'].shape[0]) + \
                     ") | options:" + command_options + " |\n"

        print(log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)

    if args.dataset_folder is None and args.preprocess_folder is None and args.preprocess_file is None and args.balance_folder is None:
        print(help_string)
    if args.dataset_type is None and args.dataset_folder is not None:
        print("Please specify the dataset type (DOS2017, DOS2018, DOS2020)!")
        print(help_string)
    if args.output_folder is None and args.balance_folder is not None:
        print("Please specify the output folder!")
        print(help_string)


# Ensure this script can run as a standalone program
if __name__ == "__main__":
    # main(sys.argv)
    # print(parse_labels('DOS2018', label=1))
    process_pcap('dataset/CIC-DDoS-2019-SynFlood.pcap', in_labels=parse_labels('DOS2018', label=1))
