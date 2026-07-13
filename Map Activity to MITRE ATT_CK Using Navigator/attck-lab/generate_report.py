#!/usr/bin/env python3
import json
from datetime import datetime

def generate_threat_report(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    
    report = f"""
THREAT INTELLIGENCE REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Campaign: {data['name']}

EXECUTIVE SUMMARY
================
This analysis maps observed ransomware activities to the MITRE ATT&CK framework,
identifying {len(data['techniques'])} distinct techniques across multiple tactics.

ATTACK PROGRESSION
==================
"""
    
    # Sort techniques by tactic order
    tactic_order = ['initial-access', 'execution', 'persistence', 'defense-evasion', 
                   'discovery', 'lateral-movement', 'collection', 'impact']
    
    tactics = {}
    for technique in data['techniques']:
        tactic = technique['tactic']
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(technique)
    
    for tactic in tactic_order:
        if tactic in tactics:
            report += f"\n{tactic.upper().replace('-', ' ')}:\n"
            for tech in tactics[tactic]:
                report += f"  {tech['techniqueID']} (Score: {tech['score']})\n"
                report += f"  └─ {tech['comment']}\n"
    
    # Recommendations
    report += """
DEFENSIVE RECOMMENDATIONS
=========================
1. Implement email security controls to prevent spearphishing
2. Deploy endpoint detection and response (EDR) solutions
3. Enable file system monitoring for encryption activities
4. Implement network segmentation to limit lateral movement
5. Maintain offline backups for rapid recovery
6. Conduct regular security awareness training

INDICATORS OF COMPROMISE
========================
- Unusual process injection activities
- Rapid file system changes indicating encryption
- Network scanning for share discovery
- Registry modifications for persistence
- Ransom note creation and display
"""
    
    return report

# Generate and save report
report_content = generate_threat_report('comprehensive_ransomware.json')
with open('threat_intelligence_report.txt', 'w') as f:
    f.write(report_content)

print("Threat intelligence report generated: threat_intelligence_report.txt")
print("\nReport preview:")
print("=" * 60)
print(report_content[:1000] + "...")
