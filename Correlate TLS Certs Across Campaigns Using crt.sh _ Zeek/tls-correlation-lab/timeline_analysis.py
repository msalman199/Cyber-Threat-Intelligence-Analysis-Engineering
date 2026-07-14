#!/usr/bin/env python3
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import os

def create_campaign_timeline():
    """Create timeline of certificate activities across campaigns"""
    
    # Load all certificate data
    all_certs = []
    
    for filename in os.listdir('analysis'):
        if filename.endswith('_details.json') and 'zeek' not in filename:
            with open(f'analysis/{filename}', 'r') as f:
                certs = json.load(f)
                all_certs.extend(certs)
    
    if not all_certs:
        print("No certificate data found for timeline analysis")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(all_certs)
    
    # Convert timestamps
    df['not_before'] = pd.to_datetime(df['not_before'])
    df['logged_at'] = pd.to_datetime(df['logged_at'])
    
    # Create timeline visualization
    plt.figure(figsize=(14, 8))
    
    # Plot certificate issuance by domain
    domains = df['domain_searched'].unique()
    colors = plt.cm.Set3(range(len(domains)))
    
    for i, domain in enumerate(domains):
        domain_certs = df[df['domain_searched'] == domain]
        plt.scatter(domain_certs['not_before'], [i] * len(domain_certs), 
                   c=[colors[i]], label=domain, alpha=0.7, s=50)
    
    plt.yticks(range(len(domains)), domains)
    plt.xlabel('Certificate Issue Date')
    plt.ylabel('Campaign Domain')
    plt.title('Certificate Issuance Timeline Across Campaigns')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig('analysis/campaign_timeline.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("Campaign timeline saved to analysis/campaign_timeline.png")
    
    # Generate timeline summary
    timeline_summary = {
        'earliest_cert': df['not_before'].min().isoformat(),
        'latest_cert': df['not_before'].max().isoformat(),
        'total_timespan_days': (df['not_before'].max() - df['not_before'].min()).days,
        'certs_per_domain': df.groupby('domain_searched').size().to_dict(),
        'monthly_activity': df.groupby(df['not_before'].dt.to_period('M')).size().to_dict()
    }
    
    # Convert Period objects to strings for JSON serialization
    timeline_summary['monthly_activity'] = {str(k): v for k, v in timeline_summary['monthly_activity'].items()}
    
    with open('analysis/timeline_summary.json', 'w') as f:
        json.dump(timeline_summary, f, indent=2)
    
    print("Timeline summary saved to analysis/timeline_summary.json")
    
    return timeline_summary

if __name__ == "__main__":
    summary = create_campaign_timeline()
    if summary:
        print("\n=== CAMPAIGN TIMELINE SUMMARY ===")
        print(f"Analysis Period: {summary['earliest_cert']} to {summary['latest_cert']}")
        print(f"Total Timespan: {summary['total_timespan_days']} days")
        print("\nCertificates per Domain:")
        for domain, count in summary['certs_per_domain'].items():
            print(f"  {domain}: {count} certificates")
