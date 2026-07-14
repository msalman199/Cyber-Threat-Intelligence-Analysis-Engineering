import pandas as pd
import numpy as np
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score, homogeneity_score, completeness_score
import matplotlib.pyplot as plt
import seaborn as sns

def evaluate_clustering_performance(true_labels, predicted_labels):
    """Evaluate clustering performance against ground truth"""
    
    # Calculate various metrics
    ari = adjusted_rand_score(true_labels, predicted_labels)
    nmi = normalized_mutual_info_score(true_labels, predicted_labels)
    homogeneity = homogeneity_score(true_labels, predicted_labels)
    completeness = completeness_score(true_labels, predicted_labels)
    
    print("Clustering Evaluation Metrics:")
    print(f"Adjusted Rand Index: {ari:.3f}")
    print(f"Normalized Mutual Information: {nmi:.3f}")
    print(f"Homogeneity Score: {homogeneity:.3f}")
    print(f"Completeness Score: {completeness:.3f}")
    
    return ari, nmi, homogeneity, completeness

def analyze_cluster_characteristics(data):
    """Analyze characteristics of each cluster"""
    
    print("\nCluster Analysis:")
    print("=" * 50)
    
    for cluster_id in sorted(data['predicted_cluster'].unique()):
        cluster_data = data[data['predicted_cluster'] == cluster_id]
        
        print(f"\nCluster {cluster_id} ({len(cluster_data)} intrusions):")
        print("-" * 30)
        
        # Most common characteristics
        print(f"Most common attack types: {cluster_data['attack_type'].value_counts().head(3).to_dict()}")
        print(f"Most common source countries: {cluster_data['source_country'].value_counts().head(3).to_dict()}")
        print(f"Most common target ports: {cluster_data['target_port'].value_counts().head(3).to_dict()}")
        
        # Statistical summaries
        print(f"Average payload size: {cluster_data['payload_size'].mean():.0f} bytes")
        print(f"Average duration: {cluster_data['duration_minutes'].mean():.1f} minutes")
        print(f"Average success rate: {cluster_data['success_rate'].mean():.2f}")
        
        # Ground truth mapping
        print(f"True campaigns in this cluster: {cluster_data['true_campaign'].value_counts().to_dict()}")

def create_confusion_matrix(data):
    """Create confusion matrix between true campaigns and predicted clusters"""
    
    # Create confusion matrix
    confusion_df = pd.crosstab(data['true_campaign'], data['predicted_cluster'], margins=True)
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(confusion_df.iloc[:-1, :-1], annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix: True Campaigns vs Predicted Clusters')
    plt.xlabel('Predicted Cluster')
    plt.ylabel('True Campaign')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    return confusion_df

# Load clustered data
data = pd.read_csv('clustered_data.csv')

print("Evaluating clustering performance...")
ari, nmi, homogeneity, completeness = evaluate_clustering_performance(
    data['true_campaign'], data['predicted_cluster']
)

print("\nAnalyzing cluster characteristics...")
analyze_cluster_characteristics(data)

print("\nCreating confusion matrix...")
confusion_matrix = create_confusion_matrix(data)
print("\nConfusion Matrix:")
print(confusion_matrix)
