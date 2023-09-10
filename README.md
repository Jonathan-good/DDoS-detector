# DDoS Detector
**note**: This project is still under development.

## Overview

This user-friendly tkinter application allows users to upload pcap (packet capture) files and analyze them using an AI-based DDoS (Distributed Denial of Service) detector. By leveraging machine learning and network analysis techniques, this tool helps identify potential DDoS attacks.

The jupyter notebook `DDoS_Detector.ipynb` contains the code for the machine learning model and some visualizations analyzing the dataset. The `app.py` file contains the code for the tkinter application. The `create_test_case.py` file contains the code for creating custom packets.

## Features

- **Upload Pcap Files**: Users can easily upload pcap files from their local devices.
- **AI-based Detection**: The application employs advanced machine learning models to detect DDoS attacks within the uploaded pcap file.
- **User-Friendly Interface**: The user interface is designed to be intuitive and straightforward.
- **Custom packets**: User can create custom packets using create_test_case.py.

## Usage

1. Clone this repository to your local machine. `git clone https://github.com/Jonathan-good/DDoS-detector.git`.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Run the application using `python app.py`.
4. Upload a pcap file using the provided interface.
5. Analyze the results, which will indicate if a DDoS attack is detected.
6. The details of the analysis will be saved in a text file in the `details` folder.
7. (Optional) Create custom packets using `create_test_case.py`.

## Steps to create custom packets

1. Run `create_test_case.py`.
2. Enter the file name for the pcap file.
3. Enter the number of packets to be created.
4. Follow the instructions to create the packets.
   * Packet example:
   * `[11335, 1, '10.0.0.1', '10.0.0.8', 4777, 5092282, 10, 711000000,
        10711000000.0, 3, 1790, 0, 0, 0, 0, 'UDP', 3, 3679, 58460931, 0,
        5232.0, 5232.0]`
5. The pcap file will be saved in the `custom_packets` folder.

## Requirements

- Python 3.x
- See requirements.txt

## Deployment

- All you need to do is run `python app.py` to start the application.

## Issues

- Everyone is welcome to open an issues to report bugs or suggest improvements.

## About the Developer

- I am a passionate cybersecurity enthusiast with a mission to utilize the power of artificial intelligence (AI) to safeguard the digital world from illegal hacking activities. I aspire to contribute to a safer, more secure digital planet. By implementing AI solutions and continuously expanding my knowledge, I am dedicated to playing a part in defending our interconnected world from cyber adversaries. Together, we can shape a more resilient and protected future online.

## Credits

Dataset: https://www.kaggle.com/datasets/aikenkazin/ddos-sdn-dataset