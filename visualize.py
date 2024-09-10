# -*- coding: utf-8 -*-
"""visualize.ipynb

Automatically generated by Colab.

Original file is located at
    https://colab.research.google.com/drive/1aEBPWn8mbzPsZ2hJLzauFjCqMMESWiLz
"""

import pandas as pd

from google.colab import files

uploaded_file = files.upload()

pip install pandas --upgrade

pip install dpkt

pip install scapy pandas

from scapy.all import rdpcap, Raw

# Load the PCAP file
packets = rdpcap('/content/1.pcap')

# Create an empty list to store packet data
packet_list = []

# Iterate through the packets and extract raw data
for pkt in packets:
    if Raw in pkt:
        packet_list.append({
            'raw_data': bytes(pkt[Raw]).hex()  # Store the raw packet data in hex format
        })

# Create a pandas DataFrame
df = pd.DataFrame(packet_list)

# Display the first few rows
print(df.head())

pip install pyshark

!pip install pyshark nest_asyncio

import pandas as pd
from scapy.all import rdpcap, Raw, IP, TCP

# Load the PCAP file
packets = rdpcap('/content/1.pcap')

# Create an empty list to store packet data
packet_list = []

# Iterate through the packets
for pkt in packets:
    if IP in pkt and TCP in pkt:
        packet_list.append({
            'src_ip': pkt[IP].src,
            'dst_ip': pkt[IP].dst,
            'src_port': pkt[TCP].sport,
            'dst_port': pkt[TCP].dport,
            'length': len(pkt)
        })
    elif Raw in pkt:
        packet_list.append({
            'raw_data': bytes(pkt[Raw]).hex()
        })

# Convert to a pandas DataFrame
df = pd.DataFrame(packet_list)

# Display the first few rows
print(df.head())

import pandas as pd
from scapy.all import rdpcap, IP, TCP

# Load the PCAP file
packets = rdpcap('/content/fuzz-2007-02-17-22957.pcap')

# Create an empty list to store parsed packet data
packet_list = []

# Iterate through the packets and extract information
for pkt in packets:
    if IP in pkt and TCP in pkt:
        # Extract IP and TCP fields
        packet_list.append({
            'src_ip': pkt[IP].src,
            'dst_ip': pkt[IP].dst,
            'src_port': pkt[TCP].sport,
            'dst_port': pkt[TCP].dport,
            'length': len(pkt)
        })
    else:
        # Store raw packet data if no IP/TCP layer is found
        packet_list.append({
            'raw_data': bytes(pkt).hex()
        })

# Convert the list to a pandas DataFrame
df = pd.DataFrame(packet_list)

# Display the first few rows
print(df.head())

from scapy.all import rdpcap

# Load the PCAP file
packets = rdpcap('/content/fuzz-2007-02-17-22957.pcap')

# Print a summary of all packets
packets.summary()

# Print details of the first 5 packets
for i, packet in enumerate(packets[:5]):
    print(f"Packet {i}:")
    packet.show()
    print("\n")

from scapy.all import Ether

packet_list = []
for pkt in packets:
    if Ether in pkt:
        packet_list.append({
            'src_mac': pkt[Ether].src,
            'dst_mac': pkt[Ether].dst,
            'length': len(pkt)
        })
    else:
        packet_list.append({
            'raw_data': bytes(pkt).hex()
        })

df = pd.DataFrame(packet_list)
print(df.head())

print(df.shape)

