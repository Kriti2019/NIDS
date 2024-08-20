import numpy as np
from gensim.models import Word2Vec
from edgeembed import edge_embeddings

# Function to calculate the importance score of an edge
def calculate_importance_score(E, t, u):
    num_edges_ending_at_u = sum(1 for edge in E if edge[1] == u)
    total_edges = len(E)
    order_of_edge = [index for index, edge in enumerate(E) if edge[0] == t and edge[1] == u][0]
    importance_score = (num_edges_ending_at_u / total_edges) * (order_of_edge / total_edges)
    return importance_score

# Function to calculate the correlation score between host t and edge e
def calculate_correlation_score(embedding_t, embedding_e, importance_score, lambda_value):
    dot_product = np.dot(embedding_t, embedding_e)
    normalization_factor = sum(np.exp(np.dot(embedding_t, embedding)) for embedding in edge_embeddings.values())
    correlation_score = (lambda_value * importance_score) + ((1 - lambda_value) * np.exp(dot_product) / normalization_factor)
    return correlation_score

# Function to compute the joint correlation score for all edges in Lt
def compute_joint_correlation_score(Lt, embeddings, lambda_value):
    correlation_scores = []
    for edge in Lt:
        embedding_e = embeddings[edge]
        importance_score = calculate_importance_score(E, edge[0], edge[1])
        correlation_score = calculate_correlation_score(embedding_t, embedding_e, importance_score, lambda_value)
        correlation_scores.append(correlation_score)
    joint_correlation_score = np.prod(correlation_scores)
    return joint_correlation_score

# Function to optimize the host representation
def optimize_host_representation(Mt):
    normalized_vector = Mt / np.linalg.norm(Mt)
    return normalized_vector

edge_embeddings = {
    # Update with your actual edge embeddings dictionary
    ('node1', 'node2'): [0.1, 0.2, 0.3, ..., 0.1],
    ('node3', 'node4'): [0.4, 0.5, 0.6, ..., 0.2],
    ('node5', 'node6'): [0.1, 0.2, 0.3, ..., 0.1],
    ('node7', 'node8'): [0.4, 0.5, 0.6, ..., 0.2],
    ('node9', 'node10'): [0.1, 0.2, 0.3, ..., 0.1],
    ('node11', 'node12'): [0.4, 0.5, 0.6, ..., 0.2],
    ('node13', 'node14'): [0.1, 0.2, 0.3, ..., 0.1],
    ('node15', 'node16'): [0.4, 0.5, 0.6, ..., 0.2]
    
}


# Initialize the Word2Vec model with the desired parameters
model = Word2Vec(size=128, window=5, min_count=1, sg=1)  

# Train the Word2Vec model on the text representations of the nodes
sentences = [[' '.join(edge_embeddings[edge])] for edge in edge_embeddings]
model.build_vocab(sentences)
model.train(sentences, total_examples=model.corpus_count, epochs=model.epochs)

# Get the optimized host representations
optimized_host_representations = {}
for t in G.nodes:  
    Lt = [edge for edge in E if edge[0] == t]  
    Mt = np.sum(edge_embeddings[edge] * np.log(lambda_value * (calculate_importance_score(E, t, edge[1]) + xi) + xi) / (calculate_importance_score(E, t, edge[1]) + xi) for edge in Lt)
    optimized_host_representation = optimize_host_representation(Mt)
    optimized_host_representations[t] = optimized_host_representation

# Print the optimized host representations
for host, representation in optimized_host_representations.items():
    print(f"Host: {host}, Representation: {representation}")
