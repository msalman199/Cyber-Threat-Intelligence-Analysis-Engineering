#!/usr/bin/env python3
import os
from datetime import datetime

def consolidate_reports():
    report_files = [
        "diamond_model_report.txt",
        "adversary_profile.txt",
        "capability_infrastructure.txt",
        "victim_gaps_analysis.txt"
    ]
    
    consolidated = f"""
COMPREHENSIVE DIAMOND MODEL THREAT INTELLIGENCE ANALYSIS
{'='*60}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
    
    for report_file in report_files:
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                consolidated += f"\n{f.read()}\n"
                consolidated += "\n" + "="*60 + "\n"
    
    # Add intelligence requirements summary
    consolidated += """
INTELLIGENCE COLLECTION PRIORITIES
==================================

IMMEDIATE REQUIREMENTS (0-30 days):
• Malware sample analysis and reverse engineering
• C2 infrastructure monitoring and takedown coordination
• Victim notification and impact assessment
• Defensive signature development

SHORT-TERM REQUIREMENTS (30-90 days):
• Attribution analysis and adversary profiling
• Campaign timeline reconstruction
• Additional victim identification
• Threat hunting rule development

LONG-TERM REQUIREMENTS (90+ days):
• Strategic adversary assessment
• Predictive analysis for future campaigns
• Industry threat landscape analysis
• Defensive capability gap assessment

RECOMMENDED ACTIONS:
• Implement network monitoring for identified IOCs
• Develop custom detection rules for observed TTPs
• Coordinate with industry partners for intelligence sharing
• Establish proactive threat hunting procedures
"""
    
    return consolidated

if __name__ == "__main__":
    report = consolidate_reports()
    print(report)
    
    with open("final_diamond_analysis.txt", "w") as f:
        f.write(report)
    
    print("\n" + "="*50)
    print("ANALYSIS COMPLETE")
    print("="*50)
    print("Final report saved to: final_diamond_analysis.txt")
