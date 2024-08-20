from scapy.all import rdpcap, SSL
from scapy.layers.ssl_tls import SSL
#tshark -r "C:\Users\kriti\OneDrive\Desktop\Thesis pcaps\Test-1.pcap" -Y "tls.record.content_type == 22" -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite
# Function to extract TLS information from packets
def extract_tls_info(pcap_file):
    tls_info = []

    # Read the pcap file
    packets = rdpcap(pcap_file)

    for packet in packets:
        if SSL in packet:
            ssl_packet = packet[SSL]
            tls_info.append({
                "TLS Version": ssl_packet.version,
                "Length": len(ssl_packet),
                # Add more fields as needed
            })

    return tls_info

# List of pcap files to process
pcap_files = [
    r"C:\Users\kriti\OneDrive\Desktop\Thesis pcaps\Test-1.pcap"
]

# Process each pcap file in the list
for pcap_file in pcap_files:
    print(f"Processing {pcap_file}...\n")
    tls_info = extract_tls_info(pcap_file)

    for i, info in enumerate(tls_info):
        print(f"TLS Packet {i + 1} Information:")
        for key, value in info.items():
            print(f"{key}: {value}")
        print("=" * 40)

    print("\n")
