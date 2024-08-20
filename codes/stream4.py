from scapy.all import rdpcap, TCP, IP, TLS, SSL
from collections import defaultdict

# Function to extract 5-tuples and integrate packets into streams
def extract_streams(pcap_file):
    streams = defaultdict(list)  # Dictionary to store streams

    # Read the pcap file
    packets = rdpcap(pcap_file)

    for packet in packets:
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            protocol = 'TCP'

            # Create a unique key for the stream based on the 5-tuple
            stream_key = (src_ip, src_port, dst_ip, dst_port, protocol)

            # Add the packet to the stream
            streams[stream_key].append(packet)

    return streams

# Function to extract TLS version and supported cipher suites from a list of packets
def extract_tls_info(packets):
    tls_info = {
        'tls_versions': set(),
        'cipher_suites': set()
    }

    for packet in packets:
        if TLS in packet or SSL in packet:
            if TLS in packet:
                tls_info['tls_versions'].add(packet[TLS].version)
            elif SSL in packet:
                tls_info['tls_versions'].add(packet[SSL].version)
            tls_info['cipher_suites'].update(packet[TLS].fields['cipher_suites'])

    return tls_info

# List of pcap files to process
pcap_files = [
    r"C:\Users\kriti\OneDrive\Desktop\Thesis pcaps\output1.pcap"
]

# Process each pcap file in the list
for pcap_file in pcap_files:
    print(f"Processing {pcap_file}...\n")
    streams = extract_streams(pcap_file)

    # Now we have a dictionary of streams, where each key is a 5-tuple, and the value is a list of packets.

    for stream_key, packets in streams.items():
        src_ip, src_port, dst_ip, dst_port, protocol = stream_key

        # Print basic information about the stream
        print(f"Stream: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
        print(f"Number of Packets: {len(packets)}")
        total_bytes = sum(len(packet) for packet in packets)
        print(f"Total Bytes: {total_bytes} bytes")

        # Extract and print TLS version and supported cipher suites
        tls_info = extract_tls_info(packets)
        print(f"TLS Versions: {', '.join(map(hex, tls_info['tls_versions']))}")
        print(f"Supported Cipher Suites: {', '.join(map(hex, tls_info['cipher_suites']))}")

        # Add a separator for clarity between different streams
        print("=" * 40)

    print("\n")
