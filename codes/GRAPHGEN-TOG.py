import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from collections import defaultdict
import placeholders as ph  # Make sure placeholders.py is available in your project directory

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

# Function to extract attributes from the network traffic data
def extract_attributes(streams):
    attributes = {}
    for index, stream in enumerate(streams):
        # Extract attributes as per your requirements
        tls_handshake_features = {
            'tls_version': stream.tls_version,
            'cipher_suites': stream.cipher_suites,
            'extensions': stream.extensions
        }
        domain_name_features = {
            'domain_length': len(stream.server_domain),
            'number_of_characters': len(stream.server_domain),
            'character_ratio': stream.character_ratio,
            'vowel_consonant_ratio': stream.vowel_consonant_ratio
        }

        # Calculate the number, length, and time interval of packets sent and received
        packet_lengths = [len(packet) for packet in stream.packets]
        time_intervals = [packet.time - stream.packets[i - 1].time for i, packet in enumerate(stream.packets) if i > 0]
        num_packets_sent = len(stream.packets)

        side_channel_features = {
            'num_packets_sent': num_packets_sent,
            'packet_lengths': packet_lengths,
            'time_intervals': time_intervals,
        }

        # Create a dictionary to store attributes for this stream
        stream_attributes = {
            'tls_handshake': tls_handshake_features,
            'domain_name': domain_name_features,
            'side_channel': side_channel_features,
            'temporal_feature': index
        }

        # Use a unique identifier for each edge (stream)
        edge_identifier = (stream.internal_host, stream.external_node)
        attributes[edge_identifier] = stream_attributes

    return attributes

# Function to generate the graph
def generate_graph(pcap_file):
    streams = extract_streams(pcap_file)

    # Create a list to store the extracted streams
    stream_objects = []

    for stream_key, packets in streams.items():
        src_ip, src_port, dst_ip, dst_port, protocol = stream_key

        # Initialize TLS handshake features
        tls_version = None
        cipher_suites = []
        extensions = {}

        # Check if the stream contains TLS packets (check for TLS ClientHello)
        for packet in packets:
            if packet.haslayer(TLSClientHello):
                tls_layer = packet[TLSClientHello]
                # Extract TLS version, cipher suites, and extensions
                tls_version = tls_layer.version
                cipher_suites = [hex(suite) for suite in tls_layer.cipher_suites]
                if tls_layer.haslayer(TLS_Ext_ServerName):
                    extensions['SNI'] = tls_layer[TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')

        # Create a Stream object to hold the information
        stream_obj = Stream(src_ip, dst_ip, tls_version, cipher_suites, extensions, packets)
        stream_objects.append(stream_obj)

    # Extract attributes from the streams
    attributes = extract_attributes(stream_objects)

    # Create a graph
    G = nx.Graph()

    for stream_obj in stream_objects:
        internal_host = stream_obj.internal_host
        external_node = stream_obj.external_node

        G.add_edge(internal_host, external_node)

    # Calculate I
    I = {edge: index for index, edge in enumerate(G.edges)}

    # Visualize the graph
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color="skyblue", node_size=1500, font_size=8)
    plt.show()

    return G, attributes, I

# Sample Stream class to hold stream information
class Stream:
    def __init__(self, internal_host, external_node, tls_version, cipher_suites, extensions, packets):
        self.internal_host = internal_host
        self.external_node = external_node
        self.tls_version = tls_version
        self.cipher_suites = cipher_suites
        self.extensions = extensions
        self.server_domain = extensions.get("SNI", external_node)
        self.packets = packets
        self.character_ratio = ph.calculate_number_character_ratio(external_node)
        self.vowel_consonant_ratio = ph.calculate_vowel_consonant_ratio(external_node)

# Main function
def main():
    pcap_file = r"C:\Users\kriti\OneDrive\Desktop\Thesis pcaps\output1.pcap"
    G, attributes, I = generate_graph(pcap_file)

    # Print the extracted attributes and I as needed
    print("Attributes:")
    for edge, attr in attributes.items():
        print(edge, attr)

    print("\nTemporal Feature I:")
    for edge, index in I.items():
        print(edge, index)

if __name__ == "__main__":
    main()
