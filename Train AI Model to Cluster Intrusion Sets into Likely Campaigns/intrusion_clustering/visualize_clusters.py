import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

def visualize_clusters_2d(features, labels, true_labels, method='PCA'):
    """Visualize clusters in 2D using dimensionality reduction"""
    
    if method == 'PCA':
        reducer = PCA(n_components=2, random_state=42)
        title_suffix = "PCA"
    else:
        reducer = TSNE(n_components=2, random_state=42, perplexity=30)
        title_suffix = "t-SNE"
    
    # Reduce dimensions
    features_2d = reducer.fit_transform(features)
    
    # Create subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Plot predicted clusters
    scatter1 = ax1.scatter(features_2d[:, 0], features_2d[:, 1], 
                          c=labels, cmap='tab10', alpha=0.7)
    ax1.set_title(f'Predicted Clusters ({title_suffix})')
    ax1.set_xlabel(f'{title_suffix} Component 1')
    ax1.set_ylabel(f'{title_suffix} Component 2')
    plt.colorbar(scatter1, ax=ax1)
    
    # Plot true campaigns
    # Create numeric labels for true campaigns
    unique_campaigns = sorted(set(true_labels))
    campaign_to_num = {campaign: i for i, campaign in enumerate(unique_campaigns)}
    true_labels_numeric = [campaign_to_num[campaign] for campaign in true_labels]
    
    scatter2 = ax2.scatter(features_2d[:, 0], features_2d[:, 1], 
                          c=true_labels_numeric, cmap='tab10', alpha=0.7)
    ax2.set_title(f'True Campaigns ({title_suffix})')
    ax2.set_xlabel(f'{title_suffix} Component 1')
    ax2.set_ylabel(f'{title_suffix} Component 2')
    
    # Create custom colorbar for true campaigns
    cbar2 = plt.colorbar(scatter2, ax=ax2)
    cbar2.set_ticks(range(len(unique_campaigns)))
    cbar2.set_ticklabels(unique_campaigns)
    
    plt.tight_layout()
    plt.savefig(f'cluster_visualization_{method.lower()}.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_cluster_summary_report(data):
    """Create comprehensive cluster summary report"""
    
    report = []
    
    for cluster_id in sorted(data['predicted_cluster'].unique()):
        cluster_data = data[data['predicted_cluster'] == cluster_id]
        
        # Calculate cluster characteristics
        summary = {
            'Cluster_ID': cluster_id,
            'Size': len(cluster_data),
            'Dominant_Attack_Type': cluster_data['attack_type'].mode().iloc[0],
            'Primary_Source_Country': cluster_data['source_country'].mode().iloc[0],
            'Common_Target_Port': cluster_data['target_port'].mode().iloc[0],
            'Avg_Payload_Size': cluster_data['payload_size'].mean(),
            'Avg_Duration_Minutes': cluster_data['duration_minutes'].mean(),
            'Avg_Success_Rate': cluster_data['success_rate'].mean(),
            'Most_Likely_Campaign': cluster_data['true_campaign'].mode().iloc[0],
            'Campaign_Purity': (cluster_data['true_campaign'] == cluster_data['true_campaign'].mode().iloc[0]).mean()
        }
        
        report.append(summary)
    
    report_df = pd.DataFrame(report)
    report_df.to_csv('cluster_summary_report.csv', index=False)
    
    print("Cluster Summary Report:")
    print("=" * 80)
    print(report_df.to_string(index=False))
    
    return report_df

# Load data and features
data = pd.read_csv('clustered_data.csv')
features_scaled = np.load('features_scaled.npy')

print("Creating cluster visualizations...")

# PCA visualization
visualize_clusters_2d(features_scaled, data['predicted_cluster'], 
                     data['true_campaign'], method='PCA')

# t-SNE visualization (may take a moment)
print("Generating t-SNE visualization (this may take a moment)...")
visualize_clusters_2d(features_scaled, data['predicted_cluster'], 
                     data['true_campaign'], method='TSNE')

print("\nGenerating cluster summary report...")
summary_report = create_cluster_summary_report(data)

print("\nVisualization and analysis complete!")
