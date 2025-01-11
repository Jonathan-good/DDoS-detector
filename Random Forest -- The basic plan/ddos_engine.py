import pandas as pd
from scapy.all import *
import struct
import warnings
import pickle

warnings.filterwarnings("ignore")


def load_model():
    model_filename = 'models/random_forest_model.pkl'
    scaler_filename = 'models/standard_scaler.pkl'
    # load
    with open(model_filename, 'rb') as f:
        loaded_model = pickle.load(f)
    with open(scaler_filename, 'rb') as f:
        loaded_scaler = pickle.load(f)
    return loaded_model, loaded_scaler


loaded_model, loaded_scaler = load_model()


def predict(packet_filename):
    # Load packets from the custom PCAP file
    packets = rdpcap(packet_filename)

    # Initialize an empty list to store the extracted data
    data_list = []

    # Iterate through each packet and extract the necessary fields
    for packet in packets:
        if Raw in packet:
            raw_layer = packet[Raw].load

            src = raw_layer[:16].rstrip(b'\x00').decode("utf-8")
            dst = raw_layer[16:32].rstrip(b'\x00').decode("utf-8")
            pktcount = struct.unpack(">I", raw_layer[32:36])[0]
            bytecount = struct.unpack(">I", raw_layer[36:40])[0]
            dur = struct.unpack(">f", raw_layer[40:44])[0]
            dur_nsec = struct.unpack(">I", raw_layer[44:48])[0]
            pktrate = struct.unpack(">I", raw_layer[48:52])[0]
            Protocol = raw_layer[52:68].rstrip(b'\x00').decode("utf-8")
            port_no = struct.unpack(">H", raw_layer[68:70])[0]
            tx_bytes = struct.unpack(">I", raw_layer[70:74])[0]
            rx_bytes = struct.unpack(">I", raw_layer[74:78])[0]

            # Create a dictionary with the extracted fields
            data_dict = {
                'src': src,
                'dst': dst,
                'pktcount': pktcount,
                'bytecount': bytecount,
                'dur': dur,
                'dur_nsec': dur_nsec,
                'pktrate': pktrate,
                'Protocol_ICMP': 1 if Protocol == 'ICMP' else 0,
                'Protocol_TCP': 1 if Protocol == 'TCP' else 0,
                'Protocol_UDP': 1 if Protocol == 'UDP' else 0,
                'port_no': port_no,
                'tx_bytes': tx_bytes,
                'rx_bytes': rx_bytes,
            }

            # Append the dictionary to the data list
            data_list.append(data_dict)

    # Create a DataFrame from the list of dictionaries
    df = pd.DataFrame(data_list)
    src = df['src']
    dst = df['dst']
    # Get the feature names used during training
    original_feature_names = loaded_scaler.feature_names_in_
    #     # Now, 'df' contains the extracted fields in the same order as your desired DataFrame
    #     print(df)
    labels = ["NOT a DDOS attack", "likely a DDOS attack"]
    X = df.drop(['src', 'dst'], axis=1)

    # Rearrange the columns in 'X' to match the original feature order
    X_reordered = X[original_feature_names]

    # Transform the new data using the loaded scaler
    scaled_new_data = loaded_scaler.transform(X_reordered)

    # Ensure that the column names match the feature names
    scaled_new_df = pd.DataFrame(scaled_new_data, columns=original_feature_names)

    # Predict using the loaded model
    predicted_labels = loaded_model.predict(scaled_new_df)

    prediction = [[src_ip, dst_ip, labels[prediction]] for src_ip, dst_ip, prediction in zip(src, dst, predicted_labels)]

    # Print the predicted labels
    infos = []

    for data_dict in data_list:
        i = 1
        info = ''
        for key, value in data_dict.items():
            if i % 2 == 0:
                info += key + ' : ' + str(value) + '\n '
            else:
                info += key + ':' + str(value) + ', '
            i += 1
        infos.append(info)
    return infos, prediction


def predict_datalist(data_list):

    # Create a DataFrame from the dict
    df = pd.DataFrame([data_list])
    src = df['src']
    dst = df['dst']
    # Get the feature names used during training
    original_feature_names = loaded_scaler.feature_names_in_
    #     # Now, 'df' contains the extracted fields in the same order as your desired DataFrame
    #     print(df)
    labels = ["NOT a DDOS attack", "likely a DDOS attack"]
    X = df.drop(['src', 'dst'], axis=1)

    # Rearrange the columns in 'X' to match the original feature order
    X_reordered = X[original_feature_names]

    # Transform the new data using the loaded scaler
    scaled_new_data = loaded_scaler.transform(X_reordered)

    # Ensure that the column names match the feature names
    scaled_new_df = pd.DataFrame(scaled_new_data, columns=original_feature_names)

    # Predict using the loaded model
    predicted_labels = loaded_model.predict(scaled_new_df)

    prediction = [[src_ip, dst_ip, labels[prediction]] for src_ip, dst_ip, prediction in zip(src, dst, predicted_labels)]

    # Print the predicted labels
    infos = []

    for data_dict in [data_list]:
        i = 1
        info = ''
        for key, value in data_dict.items():
            if i % 2 == 0:
                info += key + ' : ' + str(value) + '\n '
            else:
                info += key + ':' + str(value) + ', '
            i += 1
        infos.append(info)
    return infos, prediction
