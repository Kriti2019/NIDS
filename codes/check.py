import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from collections import defaultdict
import placeholders as ph


# Define the Stream class to hold stream information
class Stream:
    def __init__(self, internal_host, external_node, tls_version, cipher_suites, extensions):
        self.internal_host = internal_host
        self.external_node = external_node
        self.tls_version = tls_version
        self.cipher_suites = cipher_suites
        self.extensions = extensions

# Function to generate the graph
def generate_graph(pcap_file):
    packets = rdpcap(pcap_file)

    # Create a list to store the extracted streams
    streams = []

    for packet in packets:
        if IP in packet and TCP in packet:
            # Extract information from the packet and create a stream object
            internal_host = packet[IP].src
            external_node = packet[IP].dst

            # Initialize TLS handshake features
            tls_version = None
            cipher_suites = []
            extensions = {}

            # Check if the packet is using TLS (check for TLS ClientHello)
            if packet.haslayer(TLSClientHello):
                tls_layer = packet[TLSClientHello]
                # Extract TLS version, cipher suites, and extensions
                tls_version = tls_layer.version
                cipher_suites = [hex(suite) for suite in tls_layer.cipher_suites]
                if tls_layer.haslayer(TLS_Ext_ServerName):
                    extensions['SNI'] = tls_layer[TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')

            # Create a Stream object to hold the information
            stream = Stream(internal_host, external_node, tls_version, cipher_suites, extensions)
            streams.append(stream)

    # Create a graph
    G = nx.Graph()

    for stream in streams:
        internal_host = stream.internal_host
        external_node = stream.external_node

        G.add_edge(internal_host, external_node)

    # Visualize the graph without blocking the code
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color="skyblue", node_size=1500, font_size=8)
    plt.show(block=False)

# Main function
def main():
    pcap_file = r"C:\Users\kriti\OneDrive\Desktop\Thesis pcaps\Test-1.pcap"
    generate_graph(pcap_file)

if __name__ == "__main__":
    main()
