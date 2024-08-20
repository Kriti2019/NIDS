from scapy.layers.tls.handshake import TLSClientHello
from scapy.all import rdpcap
from scapy.all import *
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from collections import Counter

# Function to filter and extract TLS traffic with complete handshakes
def extract_tls_streams(pcap_file):
    tls_streams = {}  # Dictionary to store TLS streams

    # Read the pcap file
    packets = rdpcap(pcap_file)

    for packet in packets:
        if 'IP' in packet and 'TCP' in packet:
            src_ip = packet['IP'].src
            src_port = packet['TCP'].sport
            dst_ip = packet['IP'].dst
            dst_port = packet['TCP'].dport
            protocol = 'TCP'

            # Check if the packet is using TLS (check for TLS ClientHello)
            if packet.haslayer(TLSClientHello):
                tls_layer = packet[TLSClientHello]

                # Create a unique key for the TLS stream based on the 5-tuple
                stream_key = (src_ip, src_port, dst_ip, dst_port, protocol)

                # Check if the stream exists, and if not, create it
                if stream_key not in tls_streams:
                    tls_streams[stream_key] = []

                # Add the TLS packet to the stream
                tls_streams[stream_key].append(packet)

    return tls_streams

# Example usage
pcap_file = r"C:\Users\kriti\OneDrive\Desktop\Test-1.pcap"

tls_streams = extract_tls_streams(pcap_file)

# Now we have a dictionary of TLS streams with complete handshakes, where each key is a 5-tuple, and the value is a list of TLS packets.

def extract_tls_handshake_info(tls_packets):
    tls_info = {
        "tls_version": [],
        "cipher_suites": [],
        "number_of_packets": len(tls_packets),
        "total_bytes": sum(len(packet) for packet in tls_packets)
    }

    for packet in tls_packets:
        # In this context, we are assuming that the ClientHello is present, so no need to check it again.
        tls_layer = packet[TLSClientHello]
        
        # Extract and append TLS version
        tls_info["tls_version"].append(tls_layer.version)
        
        # Extract and append supported cipher suites
        if tls_layer.haslayer(TLS_Ext_ServerName):
            cipher_suites = tls_layer[TLS_Ext_ServerName].cipher_suites
            tls_info["cipher_suites"].extend(cipher_suites)

    return tls_info

# Iterate over each 5-tuple TLS stream
for stream_key, tls_packets in tls_streams.items():
    src_ip, src_port, dst_ip, dst_port, protocol = stream_key
    
    # Print basic information about the stream
    print(f"Stream: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")

    # Extract and print TLS handshake info
    tls_info = extract_tls_handshake_info(tls_packets)
    print(f"TLS Version(s): {', '.join(map(hex, set(tls_info['tls_version'])))}")
    print(f"Supported Cipher Suites: {', '.join(map(hex, set(tls_info['cipher_suites'])))}")
    print(f"Number of Packets: {tls_info['number_of_packets']}")
    print(f"Total Bytes: {tls_info['total_bytes']} bytes")

    # Add a separator for clarity between different streams
    print("=" * 40)
