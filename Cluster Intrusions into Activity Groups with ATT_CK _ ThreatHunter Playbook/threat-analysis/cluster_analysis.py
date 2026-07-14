#!/usr/bin/env python3
import json
import pandas as pd
from collections import Counter
import numpy as np
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt

def load_intrusion_data(file_path):
    """Load intrusion data from JSON file"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    return pd.DataFrame(data['intrusions'])

def create_technique_features(df):
    """Create feature vectors based on ATT&CK techniques"""
    # Convert techniques list to string for vectorization
    df['technique_string'] = df['techniques'].apply(lambda x: ' '.join(x))
    
    # Create TF-IDF vectors for techniques
    vectorizer = TfidfVectorizer()
    technique_vectors = vectorizer.fit_transform(df['technique_string'])
    
    return technique_vectors, vectorizer

def cluster_intrusions(df, n_clusters=2):
    """Cluster intrusions based on technique similarity"""
    technique_vectors, vectorizer = create_technique_features(df)
    
    # Apply K-means clustering
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    clusters = kmeans.fit_predict(technique_vectors.toarray())
    
    df['cluster'] = clusters
    return df, kmeans, vectorizer

def analyze_clusters(df):
    """Analyze cluster characteristics"""
    print("=== CLUSTER ANALYSIS RESULTS ===\n")
    
    for cluster_id in df['cluster'].unique():
        cluster_data = df[df['cluster'] == cluster_id]
        print(f"CLUSTER {cluster_id}:")
        print(f"  Intrusions: {len(cluster_data)}")
        
        # Most common techniques
        all_techniques = []
        for techniques in cluster_data['techniques']:
            all_techniques.extend(techniques)
        common_techniques = Counter(all_techniques).most_common(3)
        print(f"  Top Techniques: {common_techniques}")
        
        # Target sectors
        sectors = cluster_data['target_sector'].value_counts()
        print(f"  Target Sectors: {sectors.to_dict()}")
        
        # Common indicators
        all_indicators = []
        for indicators in cluster_data['indicators']:
            all_indicators.extend(indicators)
        common_indicators = Counter(all_indicators).most_common(3)
        print(f"  Common Indicators: {common_indicators}")
        print()

def main():
    # Load and analyze data
    df = load_intrusion_data('intrusion_data.json')
    print(f"Loaded {len(df)} intrusion records\n")
    
    # Perform clustering
    clustered_df, kmeans, vectorizer = cluster_intrusions(df)
    
    # Analyze results
    analyze_clusters(clustered_df)
    
    # Save results
    clustered_df.to_csv('clustered_intrusions.csv', index=False)
    print("Results saved to clustered_intrusions.csv")

if __name__ == "__main__":
    main()
