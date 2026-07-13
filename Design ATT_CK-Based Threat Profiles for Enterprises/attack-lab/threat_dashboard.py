#!/usr/bin/env python3
import json
import os
from datetime import datetime

class ThreatDashboard:
    def __init__(self):
        self.profiles = []
        self.alignments = []
        self.load_data()
    
    def load_data(self):
        # Load threat profiles
        profile_files = [f for f in os.listdir('.') if f.endswith('_threat_profile.json')]
        for file in profile_files:
            with open(file, 'r') as f:
                self.profiles.append(json.load(f))
        
        # Load risk alignments
        alignment_files = [f for f in os.listdir('.') if f.endswith('_risk_alignment.json')]
        for file in alignment_files:
            with open(file, 'r') as f:
                self.alignments.append(json.load(f))
    
    def generate_dashboard(self):
        dashboard = f"""
ENTERPRISE THREAT INTELLIGENCE DASHBOARD
========================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

THREAT PROFILES SUMMARY
-----------------------
Total Profiles: {len(self.profiles)}

"""
        
        for profile in self.profiles:
            dashboard += f"Profile: {profile['metadata']['profile_name']}\n"
            dashboard += f"  Industry: {profile['metadata']['target_industry']}\n"
            dashboard += f"  Risk Level: {profile['risk_assessment']['risk_level']}\n"
            dashboard += f"  Attack Vectors: {len(profile['attack_vectors'])}\n"
            dashboard += f"  Risk Score: {profile['risk_assessment']['risk_score']}/25\n\n"
        
        dashboard += "RISK ALIGNMENT SUMMARY\n"
        dashboard += "----------------------\n"
        
        for alignment in self.alignments:
            dashboard += f"Organization: {alignment['organization_type']}\n"
            dashboard += f"  Top Priority: {alignment['mitigation_priorities'][0]['tactic']}\n"
            dashboard += f"  High Priority Tactics: {len([p for p in alignment['mitigation_priorities'] if p['priority_level'] == 'High'])}\n\n"
        
        dashboard += "RECOMMENDATIONS\n"
        dashboard += "---------------\n"
        dashboard += "1. Focus on Initial Access and Persistence tactics across all profiles\n"
        dashboard += "2. Implement enhanced monitoring for high-risk attack vectors\n"
        dashboard += "3. Prioritize mitigation controls based on organizational context\n"
        dashboard += "4. Regular threat profile updates based on emerging threats\n"
        
        return dashboard
    
    def export_dashboard(self, filename='threat_intelligence_dashboard.txt'):
        dashboard = self.generate_dashboard()
        with open(filename, 'w') as f:
            f.write(dashboard)
        print(f"Dashboard exported to {filename}")
        return dashboard

if __name__ == "__main__":
    dashboard = ThreatDashboard()
    print(dashboard.export_dashboard())
