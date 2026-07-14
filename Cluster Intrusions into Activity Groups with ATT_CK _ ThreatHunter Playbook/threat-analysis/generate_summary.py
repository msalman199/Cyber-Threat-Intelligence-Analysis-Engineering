#!/usr/bin/env python3
import json
import pandas as pd
from datetime import datetime

def generate_activity_group_summary():
    """Generate comprehensive activity group analysis summary"""
    
    print("=" * 60)
    print("THREAT INTELLIGENCE ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Load clustered data
    df = pd.read_csv('clustered_intrusions.csv')
    
    print("IDENTIFIED ACTIVITY GROUPS:")
    print("-" * 30)
    
    for cluster in df['cluster'].unique():
        cluster_data = df[df['cluster'] == cluster]
        
        print(f"\nActivity Group {cluster}:")
        print(f"  Intrusion Count: {len(cluster_data)}")
        print(f"  Time Range: {cluster_data['timestamp'].min()} to {cluster_data['timestamp'].max()}")
        
        # Extract unique techniques
        all_techniques = []
        for techniques_str in cluster_data['techniques']:
            techniques = eval(techniques_str)
            all_techniques.extend(techniques)
        unique_techniques = list(set(all_techniques))
        
        print(f"  Unique Techniques: {len(unique_techniques)}")
        print(f"  Technique List: {', '.join(unique_techniques)}")
        
        # Target analysis
        targets = cluster_data['target_sector'].value_counts()
        print(f"  Primary Targets: {targets.to_dict()}")
        
        # Threat level assessment
        if len(cluster_data) >= 3 and len(unique_techniques) >= 4:
            threat_level = "HIGH"
        elif len(cluster_data) >= 2:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        print(f"  Threat Level: {threat_level}")
    
    print("\n" + "=" * 60)
    print("RECOMMENDATIONS:")
    print("=" * 60)
    print("1. Implement monitoring for identified techniques")
    print("2. Enhance detection rules for clustered activity patterns")
    print("3. Share IOCs with threat intelligence community")
    print("4. Update incident response playbooks")
    print("5. Conduct threat hunting based on identified patterns")

if __name__ == "__main__":
    generate_activity_group_summary()
