#!/usr/bin/env python3
import json
import requests
from collections import Counter

# Get data from Elasticsearch
response = requests.get('http://localhost:9200/attack-data/_search?size=1000')
data = response.json()

# Analyze risk patterns
campaigns = Counter()
tactics = Counter()
severity_counts = Counter()
high_risk_techniques = []

for hit in data['hits']['hits']:
    source = hit['_source']
    campaigns[source.get('campaign', 'Unknown')] += 1
    tactics[source.get('tactic', 'Unknown')] += 1
    severity_counts[source.get('severity', 'Unknown')] += 1
    
    if source.get('severity') in ['high', 'critical']:
        high_risk_techniques.append({
            'technique': source.get('technique_name', 'Unknown'),
            'campaign': source.get('campaign', 'Unknown'),
            'tactic': source.get('tactic', 'Unknown')
        })

print("=== RISK ANALYSIS REPORT ===")
print(f"\nTop Campaigns by Activity:")
for campaign, count in campaigns.most_common():
    print(f"  {campaign}: {count} activities")

print(f"\nMost Active Tactics:")
for tactic, count in tactics.most_common():
    print(f"  {tactic}: {count} techniques")

print(f"\nSeverity Distribution:")
for severity, count in severity_counts.most_common():
    print(f"  {severity}: {count} incidents")

print(f"\nHigh-Risk Techniques ({len(high_risk_techniques)} total):")
for technique in high_risk_techniques[:5]:  # Show top 5
    print(f"  {technique['technique']} ({technique['campaign']}) - {technique['tactic']}")

# Calculate risk score
critical_count = severity_counts.get('critical', 0)
high_count = severity_counts.get('high', 0)
total_incidents = sum(severity_counts.values())
risk_score = ((critical_count * 3) + (high_count * 2)) / total_incidents * 100

print(f"\nOverall Risk Score: {risk_score:.1f}/100")
if risk_score > 70:
    print("⚠️  HIGH RISK - Immediate attention required")
elif risk_score > 40:
    print("⚠️  MEDIUM RISK - Monitor closely")
else:
    print("✓ LOW RISK - Continue monitoring")
