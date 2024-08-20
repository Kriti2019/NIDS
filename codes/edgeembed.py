from os import path
import networkx as nx
import numpy as np
from Graphgen import generate_graph
from gensim.models import Word2Vec

# Set hyperparameters
p = 1  # Hyperparameter for selecting the next step from the neighbors of o
q = 2.0  # Hyperparameter for controlling the probability of visiting new nodes

# Set embedding hyperparameters
embedding_dim = 256  # Specify the dimensionality of the edge embeddings
num_iterations = 100  # Number of iterations for optimizing the embeddings
learning_rate = 0.1  # Learning rate for optimizing the embeddings

# Generate the graph
G, E, S, I = generate_graph(path)

# Generate the network neighborhood
Co = {u: list(G.neighbors(u)) for u in G.nodes()}
num_walks = 10  # Number of random walks for each edge

# Function to calculate the probability of selecting a certain edge from the neighbors of o
def calculate_probability(o, x, Co):
    numerator = 1 / calculate_distance(o, x)
    denominator = sum([1 / calculate_distance(y, o) for y in Co])
    return numerator / denominator

# Function to calculate the distance between two edges
def calculate_distance(u, v):
    return abs(I[u] - I[v])

# Function to generate the network neighborhood for each edge
def generate_network_neighborhood(E, Co, p, q):
    N = {}
    for u in E:
        N[u] = []
        for _ in range(num_walks):
            v = u
            for _ in range(I[u]):
                neighbors = [n for n in Co[v] if n != u]
                if v == u:
                    probabilities = [p / calculate_distance(u, n) for n in neighbors]
                else:
                    probabilities = [calculate_probability(u, v, Co[v]) for n in neighbors]
                v = np.random.choice(neighbors, p=probabilities)
            N[u].append(v)
    return N

# Function to optimize the neighborhood likelihood of all edges and update the spatio-temporal embeddings
def optimize_edge_embeddings(E, N, embedding_dim, num_iterations, learning_rate):
    r = {}
    for u in E:
        r[u] = np.random.rand(embedding_dim)
    
    for _ in range(num_iterations):
        for u in E:
            gradient = -len(N[u]) * np.log(sum([np.exp(np.dot(r[u], r[n])) for n in N[u]]))
            for n in N[u]:
                gradient += np.dot(r[u], r[n])
            r[u] += learning_rate * gradient
    
    return r

# Optimize the edge embeddings
edge_embeddings = optimize_edge_embeddings(E, N, embedding_dim, num_iterations, learning_rate)

# Initialize node embeddings using gensim
sentences = [[str(node)] for node in G.nodes()]
model = Word2Vec(sentences, vector_size=embedding_dim, window=5, min_count=1, sg=1)

# Update the edge embeddings with the initialized node embeddings
for edge in edge_embeddings:
    node1, node2 = edge
    embedding = np.mean([model.wv[node1], model.wv[node2]], axis=0)
    edge_embeddings[edge] = embedding

# Print the updated edge embeddings
for edge, embedding in edge_embeddings.items():
    print(f"Edge: {edge}, Embedding: {embedding}")
