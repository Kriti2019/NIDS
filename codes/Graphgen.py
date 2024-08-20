import networkx as nx
from scapy.all import rdpcap
import matplotlib.pyplot as plt
import placeholders as ph
from stream import gen_streams
import sys

def generate_graph(pcap_file):
    streams = gen_streams(pcap_file)

    G = nx.Graph()

    for stream_key, stream in streams.items():
        internal_host = stream.internal_host
        external_node = stream.external_node

        G.add_edge(internal_host, external_node)

    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color="skyblue", node_size=1500, font_size=8)
    plt.show()


    # Initialize the sets H, D, E, S, and I
    H = set()
    D = set()
    E = []
    S = {}
    I = {}

    # Iterate over the streams
    for index, stream in enumerate(streams.values()):
        # Add internal host and external node to respective sets
        H.add(stream.internal_host)
        D.add(stream.external_node)

        # Add edges to E set and incorporate temporal feature I and attributes S
        H_node = stream.internal_host
        D_node = stream.external_node
        E.append((H_node, D_node))  # Add edge to E set

        # Add attributes to the edge from S set
        tls_handshake_features = {
            'tls_version': stream.internal_host.tls_version,
            'cipher_suites': stream.internal_host.cipher_suites,
            'extensions': stream.internal_host.extensions
        }
        domain_name_features = {
            'domain_length': len(stream.external_node),
            'number_of_characters': len(stream.external_node),
            'character_ratio': ph.calculate_character_ratio(stream.external_node),
            'vowel_consonant_ratio': ph.calculate_vowel_consonant_ratio(stream.external_node)
        }
        side_channel_features = {
            'arrival_time': ph.calculate_arrival_time(stream),
            'packet_length': ph.calculate_packet_length(stream)
        }
        attributes = {
            'tls_handshake': tls_handshake_features,
            'domain_name': domain_name_features,
            'side_channel': side_channel_features,
            'temporal_feature': index  # Add temporal feature: Connection order of the host
        }

        S[(H_node, D_node)] = attributes  # Add attributes to S set
        I[(H_node, D_node)] = index  # Add temporal feature I

        G.add_edge(H_node, D_node, temporal_feature=index, attr_dict=attributes)

    # Add the sets H and D to the graph
    G.add_nodes_from(H, bipartite=0)
    G.add_nodes_from(D, bipartite=1)

    # Print the graph summary
    print(nx.info(G))

    # Plot the bipartite graph
    pos = nx.bipartite_layout(G, H)
    nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=500)
    plt.title('Host-Server Bipartite Graph')
    plt.show()

    # Print the attributes S and temporal feature I
    print("Attributes S:")
    for edge, attributes in S.items():
        print(edge, attributes)

    print("\nTemporal Feature I:")
    for edge, index in I.items():
        print(edge, index)

    return G, E, S, I

path = sys.argv[1]
# Call the generate_graph function and store the returned values
G, E, S, I = generate_graph(path)
