import numpy as np

from ddos_engine import predict
from create_test_cases import create_pcap_file

pred1 = predict('malicious.pcap')
print(pred1)
pred2 = predict('benign.pcap')
print(pred2)
pred3 = predict('random.pcap')
print(pred3)

custom_data = np.array([[3219, 8, '10.0.0.12', '10.0.0.5', 75251, 80217566, 167,
                        333000000, 167000000000.0, 3, 7894, 13421, 14306786, 447, 0,
                        'UDP', 1, 4246, 1562, 0, 0.0, 0.0],
                       [25170, 6, '10.0.0.8', '10.0.0.9', 813, 79674, 833, 381000000,
                        833000000000.0, 9, 3021, 29, 2842, 0, 1, 'ICMP', 1, 86929, 82862,
                        0, 0.0, 0.0],
                       [30441, 6, '10.0.0.14', '10.0.0.10', 37403, 38973926, 142,
                        707000000, 143000000000.0, 11, 4920, 7754, 8079668, 258, 1,
                        'ICMP', 1, 104499, 100348, 0, 0.0, 0.0],
                       [24600, 4, '10.0.0.4', '10.0.0.8', 16084, 16759528, 58, 66000000,
                        58066000000.0, 5, 2997, 8171, 8514182, 272, 1, 'ICMP', 1, 5247,
                        1332, 0, 0.0, 0.0],
                       [16055, 2, '10.0.0.2', '10.0.0.8', 107649, 5813046, 388,
                        231000000, 388000000000.0, 3, 16540, 7651, 413154, 255, 1, 'TCP',
                        2, 26578347, 305147969, 119, 110.0, 229.0],
                       [24870, 3, '10.0.0.4', '10.0.0.8', 92360, 96239120, 331,
                        333000000, 331000000000.0, 5, 2997, 8813, 9183146, 293, 1,
                        'ICMP', 1, 5520, 1242, 0, 0.0, 0.0],
                       [8107, 9, '10.0.0.3', '10.0.0.16', 120264, 6975312, 454, 95000000,
                        454000000000.0, 5, 25224, 7170, 415860, 239, 1, 'TCP', 3,
                        25990895, 28652635, 207, 223.0, 430.0],
                       [9996, 4, '10.0.0.12', '10.0.0.7', 134772, 143666952, 311,
                        877000000, 312000000000.0, 6, 1931, 7464, 7956624, 248, 0, 'UDP',
                        2, 3413, 3539, 0, 0.0, 0.0]])


create_pcap_file('custom.pcap', custom_data)
pred4 = predict('custom.pcap')
print(pred4)