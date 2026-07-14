import pandas as pd
import numpy as np
from datetime import datetime

def generate_campaign_intelligence_report(data):
    """Generate comprehensive campaign intelligence report"""
    
    report_content = []
    
    # Header
    report_content.append("INTRUSION CAMPAIGN CLUSTERING ANALYSIS REPORT")
    report_content.append("=" * 60)
    report_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_content.append(f"Total Intrusions Analyzed: {len(data)}")
    report_content.append(f"Clusters Identified: {data['predicted_cluster'].nunique()}")
    report_content.append("")
    
    # Executive Summary
    report_content.append("EXECUTIVE SUMMARY")
    report_content.append("-" * 20)
    
    # Calculate overall statistics
    total_campaigns = data['true_campaign'].nunique()
    total_clusters = data['predicted_cluster'].nunique()
    
    report_content.append(f"• Analyzed {len(data)} intrusion events")
    report_content.append(f"• Identified {total_clusters} distinct attack patterns")
    report_content.append(f"• Ground truth contains {total_campaigns} known campaigns")
    report_content.append("")
    
    # Cluster Analysis
    report_content.append("DETAILED CLUSTER ANALYSIS")
    report_content.append("-" * 30)
    
    for cluster_id in sorted(data['predicted_cluster'].unique()):
        cluster_data = data[data['predicted_cluster'] == cluster_id]
        
        report_content.append(f"\nCLUSTER {cluster_id} - THREAT PROFILE")
        report_content.append("~" * 35)
        
        # Basic statistics
        report_content.append(f"Size: {len(cluster_data)} intrusions ({len(cluster_data)/len(data)*100:.1f}% of total)")
        
        # Attack characteristics
        top_attack_type = cluster_data['attack_type'].mode().iloc[0]
        attack_type_pct = (cluster_data['attack_type'] == top_attack_type).mean() * 100
        report_content.append(f"Primary Attack Vector: {top_attack_type} ({attack_type_pct:.1f}% of cluster)")
        
        # Geographic analysis
        top_country = cluster_data['source_country'].mode().iloc[0]
        country_pct = (cluster_data['source_country'] == top_country).mean() * 100
        report_content.append(f"Primary Source Region: {top_country} ({country_pct:.1f}% of cluster)")
        
        # Technical characteristics
        report_content.append(f"Average Payload Size: {cluster_data['payload_size'].mean():.0f} bytes")
        report_content.append(f"Average Attack Duration: {cluster_data['duration_minutes'].mean():.1f} minutes")
        report_content.append(f"Success Rate: {cluster_data['success_rate'].mean():.2%}")
        
        # Target analysis
        top_ports = cluster_data['target_port'].value_counts().head(3)
        report_content.append(f"Primary Target Ports: {', '.join([f'{port}({count})' for port, count in top_ports.items()])}")
        
        # Campaign mapping
        likely_campaign = cluster_data['true_campaign'].mode().iloc[0]
        campaign_confidence = (cluster_data['true_campaign'] == likely_campaign).mean()
        report_content.append(f"Most Likely Campaign: {likely_campaign} (confidence: {campaign_confidence:.2%})")
        
        # Threat assessment
        if campaign_confidence > 0.8:
            threat_level = "HIGH - Well-defined campaign pattern"
        elif campaign_confidence > 0.6:
            threat_level = "MEDIUM - Probable campaign with some variation"
        else:
            threat_level = "LOW - Mixed activities or noise"
        
        report_content.append(f"Threat Assessment: {threat_level}")
        report_content.append("")
    
    # Recommendations
    report_content.append("SECURITY RECOMMENDATIONS")
    report_content.append("-" * 25)
    
    # Analyze each cluster for recommendations
    for cluster_id in sorted(data['predicted_cluster'].unique()):
        cluster_data = data[data['predicted_cluster'] == cluster_id]
        likely_campaign = cluster_data['true_campaign'].mode().iloc[0]
        
        if 'APT' in likely_campaign:
            recommendation = "• Implement advanced persistent threat monitoring and lateral movement detection"
        elif 'Ransomware' in likely_campaign:
            recommendation = "• Enhance backup systems and implement behavioral analysis for file encryption detection"
        elif 'Botnet' in likely_campaign:
            recommendation = "• Deploy network traffic analysis and implement rate limiting for suspicious activities"
        elif 'Phishing' in likely_campaign:
            recommendation = "• Strengthen email security and implement user awareness training programs"
        else:
            recommendation = "• Monitor for anomalous activities and implement general security hardening"
        
        report_content.append(f"Cluster {cluster_id}: {recommendation}")
    
    report_content.append("")
    report_content.append("TECHNICAL NOTES")
    report_content.append("-" * 15)
    report_content.append("• Clustering performed using K-means algorithm with standardized features")
    report_content.append("• Optimal cluster count determined using silhouette analysis")
    report_content.append("• Results should be validated with additional threat intelligence")
    report_content.append("• Regular model retraining recommended as new attack patterns emerge")
    
    # Save report
    with open('campaign_intelligence_report.txt', 'w') as f:
        f.write('\n'.join(report_content))
    
    # Print to console
    for line in report_content:
        print(line)
    
    return report_content

# Load clustered data
data = pd.read_csv('clustered_data.csv')

print("Generating comprehensive campaign intelligence report...")
report = generate_campaign_intelligence_report(data)

print(f"\nReport saved as 'campaign_intelligence_report.txt'")
print("Analysis complete!")
