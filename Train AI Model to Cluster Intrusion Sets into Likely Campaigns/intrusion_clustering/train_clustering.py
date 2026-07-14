import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score, adjusted_rand_score
import matplotlib.pyplot as plt
import seaborn as sns

def find_optimal_clusters(features, max_clusters=10):
    """Find optimal number of clusters using elbow method and silhouette analysis"""
    
    inertias = []
    silhouette_scores = []
    k_range = range(2, max_clusters + 1)
    
    for k in k_range:
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
        cluster_labels = kmeans.fit_predict(features)
        
        inertias.append(kmeans.inertia_)
        silhouette_scores.append(silhouette_score(features, cluster_labels))
    
    # Plot results
    plt.figure(figsize=(12, 5))
    
    plt.subplot(1, 2, 1)
    plt.plot(k_range, inertias, 'bo-')
    plt.xlabel('Number of Clusters (k)')
    plt.ylabel('Inertia')
    plt.title('Elbow Method for Optimal k')
    plt.grid(True)
    
    plt.subplot(1, 2, 2)
    plt.plot(k_range, silhouette_scores, 'ro-')
    plt.xlabel('Number of Clusters (k)')
    plt.ylabel('Silhouette Score')
    plt.title('Silhouette Analysis')
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig('cluster_optimization.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    # Find optimal k (highest silhouette score)
    optimal_k = k_range[np.argmax(silhouette_scores)]
    print(f"Optimal number of clusters: {optimal_k}")
    print(f"Best silhouette score: {max(silhouette_scores):.3f}")
    
    return optimal_k, silhouette_scores

def train_clustering_model(features, n_clusters):
    """Train K-means clustering model"""
    
    # Train the model
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    cluster_labels = kmeans.fit_predict(features)
    
    # Calculate metrics
    silhouette_avg = silhouette_score(features, cluster_labels)
    
    print(f"Clustering Results:")
    print(f"Number of clusters: {n_clusters}")
    print(f"Silhouette score: {silhouette_avg:.3f}")
    print(f"Cluster distribution: {np.bincount(cluster_labels)}")
    
    return kmeans, cluster_labels

# Load prepared features
features_scaled = np.load('features_scaled.npy')
processed_data = pd.read_csv('processed_data.csv')

print("Finding optimal number of clusters...")
optimal_k, silhouette_scores = find_optimal_clusters(features_scaled)

print("\nTraining clustering model...")
kmeans_model, cluster_labels = train_clustering_model(features_scaled, optimal_k)

# Add cluster labels to data
processed_data['predicted_cluster'] = cluster_labels

# Save results
processed_data.to_csv('clustered_data.csv', index=False)
np.save('cluster_labels.npy', cluster_labels)

print("Clustering model training complete!")
